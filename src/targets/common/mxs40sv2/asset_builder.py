"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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
from .asset import Asset


class AssetBuilder:
    def __init__(self, policy_parser, assets_list, asset_map, **kwargs):
        self.assets_dict = {}
        self.all_assets = asset_map.get(policy_parser, **kwargs)
        for item in assets_list:
            self.assets_dict[item] = self.all_assets[item]

    def get_assets(self):
        """
        Creates a list of assets and sort it by order
        :return: Return a byte-array value representing a value of single Asset
        """
        assets = []
        for _, v in self.assets_dict.items():
            assets.append(Asset(v))
        value = bytes()
        for item in assets:
            value += item.value
        return value
