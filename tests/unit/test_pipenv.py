# This file is part of CycloneDX Python
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


from logging import getLogger
from unittest import TestCase

from cyclonedx.model.component import ComponentScope

from cyclonedx_py._internal.pipenv import PipenvBB


class TestPipenvComponentScope(TestCase):

    def test_develop_only_packages_are_excluded(self) -> None:
        locker = {
            '_meta': {'sources': [{'name': 'pypi', 'url': 'https://pypi.org/simple'}]},
            'default': {
                'runtime-only': {'version': '==1.0.0'},
                'Shared_Package': {'version': '==2.0.0'},
            },
            'develop': {
                'dev-only': {'version': '==3.0.0'},
                'shared-package': {'version': '==2.0.0'},
                'docs-and-dev': {'version': '==4.0.0'},
            },
            'docs': {
                'docs-and-dev': {'version': '==4.0.0'},
            },
        }
        bom = PipenvBB(logger=getLogger(__name__), pypi_url=None)._make_bom(
            None, locker, frozenset({'default', 'develop', 'docs'}))
        scopes = {c.name: c.scope for c in bom.components}
        self.assertDictEqual({
            'runtime-only': None,
            'Shared_Package': None,
            'dev-only': ComponentScope.EXCLUDED,
            'docs-and-dev': None,
        }, scopes)

    def test_without_develop_group_nothing_is_excluded(self) -> None:
        locker = {
            '_meta': {'sources': [{'name': 'pypi', 'url': 'https://pypi.org/simple'}]},
            'default': {'runtime-only': {'version': '==1.0.0'}},
        }
        bom = PipenvBB(logger=getLogger(__name__), pypi_url=None)._make_bom(
            None, locker, frozenset({'default'}))
        self.assertListEqual([None], [c.scope for c in bom.components])
