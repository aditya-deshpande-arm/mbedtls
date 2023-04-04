#!/usr/bin/env python3

"""
Purpose

This script is for comparing the size of the library files from two
different Git revisions within an Mbed TLS repository.
The results of the comparison is formatted as csv and stored at a
configurable location.
Note: must be run from Mbed TLS root.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import subprocess
import sys

from mbedtls_dev import build_tree

class Size:
    def __init__(self, text: int, data: int, bss: int, total: int):
        self.text = text
        self.data = data
        self.bss = bss
        self.total = total
    def __eq__(self, __o: object) -> bool:
        return (self.text == __o.text) and \
               (self.data == __o.data) and \
               (self.bss == __o.bss)

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __lt__(self, __o: object) -> bool:
        return self.total < __o.total

    def __le__(self, __o: object) -> bool:
        return self.__lt__(__o) or self.__eq__(__o)

    def __gt__(self, __o: object) -> bool:
        return self.total > __o.total

    def __ge__(self, __o: object) -> bool:
        return self.__gt__(__o) or self.__eq__(__o)

    def __add__(self, __o: object) -> object:
        text = self.text + __o.text
        data = self.data + __o.data
        bss = self.bss + __o.bss
        total = self.total + __o.total
        return Size(text,data,bss,total)

    def __sub__(self, __o: object) -> object:
        text = self.text - __o.text
        data = self.data - __o.data
        bss = self.bss - __o.bss
        total = self.total - __o.total
        return Size(text,data,bss,total)

class CodeSizeComparison:
    """Compare code size between two Git revisions."""

    def __init__(self, old_revision, new_revision, result_dir):
        """
        old_revision: revision to compare against
        new_revision:
        result_dir: directory for comparison result
        """
        self.repo_path = "."
        self.result_dir = os.path.abspath(result_dir)
        os.makedirs(self.result_dir, exist_ok=True)

        self.csv_dir = os.path.abspath("code_size_records/")
        os.makedirs(self.csv_dir, exist_ok=True)

        self.old_rev = old_revision
        self.new_rev = new_revision
        self.git_command = "git"
        self.make_command = "make"

        self.old_sizes = {}
        self.new_sizes = {}
        self.change_pcts = {}

    @staticmethod
    def validate_revision(revision):
        result = subprocess.check_output(["git", "rev-parse", "--verify",
                                          revision + "^{commit}"], shell=False)
        return result

    def _create_git_worktree(self, revision):
        """Make a separate worktree for revision.
        Do not modify the current worktree."""

        if revision == "current":
            print("Using current work directory.")
            git_worktree_path = self.repo_path
        else:
            print("Creating git worktree for", revision)
            git_worktree_path = os.path.join(self.repo_path, "temp-" + revision)
            subprocess.check_output(
                [self.git_command, "worktree", "add", "--detach",
                 git_worktree_path, revision], cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )
        return git_worktree_path

    def _build_libraries(self, git_worktree_path):
        """Build libraries in the specified worktree."""

        my_environment = os.environ.copy()
        subprocess.check_output(
            [self.make_command, "-j", "lib"], env=my_environment,
            cwd=git_worktree_path, stderr=subprocess.STDOUT,
        )

    def _gen_code_size_report(self, revision, git_worktree_path):
        """Generate a code size report for each executable and store them
        in a dictionary"""
        if revision == "current":
            print("Measuring code size in current work directory.")
        else:
            print("Measuring code size for", revision)

        # Size for libmbedcrypto.a
        result = subprocess.check_output(
            ["size -t library/libmbedcrypto.a"], cwd=git_worktree_path, shell=True
        )
        crypto_text = result.decode()
        # Size for libmbedx509.a
        result = subprocess.check_output(
            ["size -t library/libmbedx509.a"], cwd=git_worktree_path, shell=True
        )
        x509_text = result.decode()
        # Size for libmbedtls.a
        result = subprocess.check_output(
            ["size -t library/libmbedtls.a"], cwd=git_worktree_path, shell=True
        )
        tls_text = result.decode()

        def size_text_to_dict(txt):
            """Helper function: Converts 'size' command output to dictionary"""
            size_dict = {}
            for line in txt.splitlines()[1:]:
                data = line.split()
                exe_size = Size(data[0], data[1], data[2], data[3])
                size_dict[f'{data[5]}'] = exe_size
            return size_dict

        lst = [(crypto_text),(x509_text),(tls_text)]
        size_lst = [size_text_to_dict(t) for t in lst]
        size_dicts = {
            'crypto': size_lst[0],
            'x509': size_lst[1],
            'tls': size_lst[2]
        }

        if revision == self.old_rev:
            self.old_sizes = size_dicts
        if revision == self.new_rev:
            self.new_sizes = size_dicts

        return size_dicts

    def _gen_code_size_csv(self, revision, git_worktree_path):
        """Generate code size csv file."""

        csv_fname = revision + ".csv"
        if revision == "current":
            print("Measuring code size in current work directory.")
        else:
            print("Measuring code size for", revision)
        sizes_dict = self._gen_code_size_report(revision, git_worktree_path)

        def write_dict_to_csv(d):
            for (f,s) in d.items():
                csv_file.write(f'{f}, {s.text}, {s.data}, {s.bss}, {s.total}\n')

        csv_file = open(os.path.join(self.csv_dir, csv_fname), "w")
        csv_file.write('file, text, data, bss, TOTAL\n')
        for (n,d) in sizes_dict.items():
            csv_file.write(f'{n}\n')
            write_dict_to_csv(d)
            csv_file.write('\n')


    def _remove_worktree(self, git_worktree_path):
        """Remove temporary worktree."""
        if git_worktree_path != self.repo_path:
            print("Removing temporary worktree", git_worktree_path)
            subprocess.check_output(
                [self.git_command, "worktree", "remove", "--force",
                 git_worktree_path], cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )

    def _get_code_size_for_rev(self, revision):
        """Generate code size csv file for the specified git revision."""

        # Check if the corresponding record exists
        csv_fname = revision + ".csv"
        if (revision != "current") and \
           os.path.exists(os.path.join(self.csv_dir, csv_fname)):
            print("Code size csv file for", revision, "already exists.")
        else:
            git_worktree_path = self._create_git_worktree(revision)
            self._build_libraries(git_worktree_path)
            self._gen_code_size_report(revision, git_worktree_path)
            self._gen_code_size_csv(revision, git_worktree_path)
            self._remove_worktree(git_worktree_path)

    def compare_code_size(self):
        """Generate results of the size changes between two revisions,
        old and new. Measured code size results of these two revisions
        must be available."""

        res_file = open(os.path.join(self.result_dir, "compare-" + self.old_rev
                                     + "-" + self.new_rev + ".csv"), "w")
        def write_dict_to_csv(old_d, new_d):
            tot_change_pct = ""
            for (f,s) in new_d.items():
                new_size = int(s.total)
                if f in old_d:
                    old_size = int(old_d[f].total)
                    change = new_size - old_size
                    change_pct = change / old_size
                    res_file.write("{}, {}, {}, {}, {:.2%}\n".format(f, \
                               new_size, old_size, change, float(change_pct)))
                    if f == "(TOTALS)":
                        tot_change_pct = str(change_pct)
                else:
                    res_file.write("{}, {}\n".format(f, new_size))
            return tot_change_pct

        res_file.write("file_name, this_size, old_size, change, change %\n")
        print("Generating comparison results.")

        for exe in self.new_sizes:
            res_file.write(f"{exe}\n")
            tot = write_dict_to_csv(self.old_sizes[f'{exe}'], self.new_sizes[f'{exe}'])
            res_file.write('\n')
            self.change_pcts[f'{exe}'] = tot

        return 0

    def get_comparision_results(self):
        """Compare size of library/*.o between self.old_rev and self.new_rev,
        and generate the result file."""
        build_tree.check_repo_path()
        self._get_code_size_for_rev(self.old_rev)
        self._get_code_size_for_rev(self.new_rev)
        return self.compare_code_size()

def main():
    parser = argparse.ArgumentParser(
        description=(
            """This script is for comparing the size of the library files
            from two different Git revisions within an Mbed TLS repository.
            The results of the comparison is formatted as csv, and stored at
            a configurable location.
            Note: must be run from Mbed TLS root."""
        )
    )
    parser.add_argument(
        "-r", "--result-dir", type=str, default="comparison",
        help="directory where comparison result is stored, \
              default is comparison",
    )
    parser.add_argument(
        "-o", "--old-rev", type=str, help="old revision for comparison.",
        required=True,
    )
    parser.add_argument(
        "-n", "--new-rev", type=str, default=None,
        help="new revision for comparison, default is the current work \
              directory, including uncommitted changes."
    )
    comp_args = parser.parse_args()

    if os.path.isfile(comp_args.result_dir):
        print("Error: {} is not a directory".format(comp_args.result_dir))
        parser.exit()

    validate_res = CodeSizeComparison.validate_revision(comp_args.old_rev)
    old_revision = validate_res.decode().replace("\n", "")

    if comp_args.new_rev is not None:
        validate_res = CodeSizeComparison.validate_revision(comp_args.new_rev)
        new_revision = validate_res.decode().replace("\n", "")
    else:
        new_revision = "current"

    result_dir = comp_args.result_dir
    size_compare = CodeSizeComparison(old_revision, new_revision, result_dir)
    return_code = size_compare.get_comparision_results()
    sys.exit(return_code)


if __name__ == "__main__":
    main()
