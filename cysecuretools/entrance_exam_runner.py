"""
Copyright (c) 2018-2019 Cypress Semiconductor Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import sys
from cysecuretools.execute.enums import EntranceExamErrors
from cysecuretools.execute.programmer.programmer import ProgrammingTool
from cysecuretools.execute.entrance_exam import entrance_exam

TOOL_NAME = 'pyocd'  # Programming/debugging tool used for communication with device


def main(target):
    """
    Provides high level support for entrance exam procedure.
    """
    status = False
    tool = ProgrammingTool.create(TOOL_NAME)
    if tool.connect(target):
        status = entrance_exam(tool)
        tool.disconnect()

    sys.exit(0 if status == EntranceExamErrors.OK else 1)


if __name__ == "__main__":
    main()
