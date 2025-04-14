"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Huntress HEC Plugin for Netskope
"""

import json
import time
import traceback
import uuid
from datetime import datetime
from typing import List
from urllib.parse import urlparse

from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult

from .utils.constant import (
    CE_LOG_SOURCE,
    CE_LOG_SOURCE_IDENTIFIER,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)
from .utils.exception import (
    HuntressHECException,
    MappingValidationError,
)
from .utils.helper import HuntressHECPluginHelper
from .utils.utilities import get_huntress_hec_mappings, split_into_size
from .utils.validator import HuntressHECValidator


class HuntressHECPlugin(PluginBase):
    """The Huntress HEC plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Huntress HEC plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.huntress_hec_helper = HuntressHECPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = HuntressHECPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLATFORM_NAME, PLUGIN_VERSION

    @staticmethod
    def get_subtype_mapping(mappings: dict, subtype: str):
        """
        Retrieve subtype mappings (mappings for subtypes of alerts/events)

        Args:
            mappings (dict): Mapping JSON from which subtypes are to be
            retrieved.
            subtype (str): Subtype (e.g. DLP for alerts) for which the mapping
            is to be fetched

        Returns:
            Dict: Mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def map_json_data(self, mappings: dict, data: dict) -> dict:
        """Filter the raw data and returns the filtered data.

        Args:
            mappings (dict): List of fields to be pushed
            data (dict): Data to be mapped (retrieved from Netskope)

        Returns:
            dict: Mapped Dictionary.
        """
        if mappings == [] or not data:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def _filter_events(self, events: list) -> tuple:
        """Filter the raw data and returns the filtered data.

        Args:
            events (list): List of events.

        Returns:
            tuple: skipped_logs_empty, skipped_logs_timestamp, data
        """
        skipped_logs_timestamp = 0
        skipped_logs_empty = 0
        data = []
        for event in events:
            if event:
                if event.get("timestamp"):
                    data.append(event)
                else:
                    skipped_logs_timestamp += 1
            else:
                skipped_logs_empty += 1

        return skipped_logs_empty, skipped_logs_timestamp, data

    def transform(self, raw_data: List, data_type: str, subtype: str) -> List:
        """Transform Netskope data (alerts and events)
        into Huntress HEC Compatible data.

        Args:
            raw_data (List): Raw Data list pulled from tenant.
            data_type (str): Data type.
            subtype (str): Sub type.

        Returns:
            List: List of transformed logs.

        Different cases related mapping file:
            1. If mapping file is not found or contains invalid JSON,
            all the data will be ingested
            2. If the file contains few valid fields, only that
            fields will be considered for ingestion
            3. Fields which are not in Netskope response,
            but are present in mappings file will be ignored with logs.
        """
        if not self.configuration.get("transformData", True):
            try:
                (
                    delimiter,
                    cef_version,
                    huntress_hec_mappings,
                ) = get_huntress_hec_mappings(self.mappings, "json")
            except KeyError as err:
                err_msg = f"Error in {PLATFORM_NAME} mapping file."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise HuntressHECException(err_msg)
            except MappingValidationError as err:
                err_msg = (
                    f"Validation error occurred for {PLATFORM_NAME}"
                    " mapping file."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise HuntressHECException(err_msg)
            except Exception as err:
                err_msg = (
                    "An error occurred while mapping data using "
                    "given json mappings."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise HuntressHECException(err_msg)

            try:
                subtype_mapping = self.get_subtype_mapping(
                    huntress_hec_mappings["json"][data_type], subtype
                )
            except Exception:
                err_msg = (
                    "Error occurred while retrieving subtype mappings "
                    f"for datatype: {data_type} (subtype: {subtype})"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Transformation will"
                        " be skipped."
                    ),
                    details=traceback.format_exc(),
                )
                raise HuntressHECException(err_msg)

            transformed_data = []
            (
                skipped_logs_empty,
                skipped_logs_timestamp,
                data,
            ) = self._filter_events(raw_data)

            if not subtype_mapping:
                if skipped_logs_empty + skipped_logs_timestamp > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Plugin couldn't process "
                        f"{skipped_logs_empty} record(s) because they "
                        f"either had no data and {skipped_logs_timestamp}"
                        " record(s) of raw data has no timestamp field. "
                        "Therefore, the transformation and ingestion "
                        "for those record(s) were skipped."
                    )
                return data

            for item in data:
                mapped_dict = self.map_json_data(subtype_mapping, item)
                if mapped_dict:
                    transformed_data.append(mapped_dict)
                else:
                    skipped_logs_empty += 1

            if skipped_logs_empty + skipped_logs_timestamp > 0:
                self.logger.info(
                    f"{self.log_prefix}: Plugin couldn't process "
                    f"{skipped_logs_empty} record(s) because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping and "
                    f"{skipped_logs_timestamp} record(s) of raw data has "
                    "no timestamp field. Therefore, the transformation and"
                    " ingestion for those record(s) were skipped."
                )
            return transformed_data
        else:
            err_msg = (
                "The plugin only supports sharing raw JSON "
                "logs. Please disable the 'Transform the raw logs' toggle in "
                "the Basic plugin configuration."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise HuntressHECException(err_msg)

    def get_tenant_name(self, source) -> str:
        """Get Tenant Name.

        Args:
            source (str): Source configuration name.

        Returns:
            str: Tenant Name
        """
        helper = AlertsHelper()
        return str(helper.get_tenant_cls(source).name)

    def push(self, transformed_data: List, data_type: str, subtype: str):
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (List): Transformed data.
            data_type (str): Data Type.
            subtype (str): Subtype.
        """
        uid = uuid.uuid1()
        log_msg = f"{self.log_prefix}: [{data_type}] [{subtype}] -"

        self.logger.debug(
            f"{log_msg} Received {len(transformed_data)} logs to "
            f"push to {self.plugin_name}. UUID: {uid}"
        )

        url = self.configuration.get("api_url", "").strip("/").strip()
        log_source_identifier = self.configuration.get(
            "log_source_identifier", CE_LOG_SOURCE_IDENTIFIER
        ).strip()
        tenant_name = None
        if data_type != "webtx":
            tenant_name = self.get_tenant_name(self.source)
        log_fields = {
            "#ce_log_source": CE_LOG_SOURCE,
            "#ce_log_source_identifier": log_source_identifier,
        }
        if tenant_name:
            log_fields["#ce_tenant_name"] = tenant_name

        try:
            self.data_length = len(transformed_data)
            self.data_type = data_type
            self.subtype = subtype
            headers = {
                "Authorization": f"Bearer {self.configuration.get('token')}",
                "Content-Type": "application/json",
            }
            self.logger.debug(
                f"{log_msg} Initiating the ingestion of "
                f"{len(transformed_data)} log(s) to {PLATFORM_NAME}."
                f" UUID: {uid}"
            )

            count = 0
            if transformed_data:
                start = time.time()
                batch = 1
                for chunk in split_into_size(transformed_data, log_fields):
                    chunk_size = len(chunk)
                    payload_str = "\n".join(chunk)
                    batch_start = time.time()
                    size = round(len(payload_str) / 1000, 2)
                    self.huntress_hec_helper.api_helper(
                        url=url,
                        method="POST",
                        headers=headers,
                        data=payload_str,
                        proxies=self.proxy,
                        verify=True,
                        logger_msg=(
                            f"ingesting {len(chunk)} log(s) of "
                            f'datatype "{data_type}" and subtype '
                            f'"{subtype}" in batch {batch} into '
                            f'{PLATFORM_NAME} having UUID "{uid}"'
                        ),
                        show_data=False,
                    )
                    batch_end = time.time()
                    count += chunk_size
                    time_taken = round(batch_end - batch_start, 2)

                    self.logger.debug(
                        f"{log_msg} Successfully ingested {chunk_size} "
                        f"log(s) of size {size} KB in batch {batch} "
                        f"having UUID {uid} to {PLATFORM_NAME}. Time "
                        f"taken to ingest {chunk_size} log(s) is "
                        f"{time_taken} seconds."
                    )
                    self.logger.info(
                        f"{log_msg} Successfully ingested {chunk_size} "
                        f"log(s) in batch {batch}. Total log(s) pushed: "
                        f"{count}. UUID: {uid}"
                    )
                    batch += 1
                end = time.time()
                self.logger.info(
                    f"{log_msg} Successfully ingested {count} log(s) "
                    f"to {PLATFORM_NAME}. Time taken to ingest {count}"
                    f" log(s) is {round(end - start, 2)} seconds."
                )

            else:
                self.logger.info(
                    f"{log_msg} Received empty transformed data hence"
                    f" the record(s) were skipped. UUID: {uid}."
                )
        except HuntressHECException as err:
            raise err
        except Exception as err:
            # Raise this exception from here so that it does not update
            # the checkpoint, as this means data ingestion is failed
            # even after a few retries.
            err_msg = (
                f"Could not ingest data into {self.plugin_name}. UUID: {uid}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise HuntressHECException(err_msg)

    def validate_auth(
        self, url: str, token: str, log_source_identifier: str
    ) -> ValidationResult:
        """Validate the authentication credentials.

        Args:
            url (str): API URL.
            token (str): API Token.
            log_source_identifier (str): Log Source Identifier.

        Returns:
            ValidationResult: ValidationResult object with success flag and message.
        """
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            log_fields = {
                "#ce_log_source": CE_LOG_SOURCE,
                "#ce_log_source_identifier": log_source_identifier,
            }
            payload = {
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "message": "Validation event from Netskope CE",
                "severity": "info",
                "source": "netskope-ce",
                "sourcetype": "netskope:ce:validation",
                "event_type": "validation",
            }
            payload.update(log_fields)
            payload_str = json.dumps(payload)
            self.huntress_hec_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                data=payload_str,
                proxies=self.proxy,
                verify=True,
                logger_msg="validating authentication credentials",
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        except HuntressHECException as err:
            err_msg = f"Validation error occurred. {err}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except Exception as err:
            err_msg = f"Validation error occurred. {err}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using the urllib.parse library.

        Args:
            url (str): URL to be validated.

        Returns:
            bool: True if URL is valid, False otherwise.
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: ValidationResult object with success flag and message.
        """
        huntress_hec_validator = HuntressHECValidator(
            self.logger, self.log_prefix
        )
        url = configuration.get("api_url", "").strip().rstrip("/")
        validation_err_msg = "Validation error occurred,"

        if configuration.get("transformData", True):
            log_msg = (
                "The plugin only supports sharing raw JSON logs. "
                "Please disable the 'Transform the raw logs' toggle to save "
                "the configuration."
            )
            self.logger.error(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(
                success=False,
                message=log_msg,
            )
        # Validate URL
        if not url:
            err_msg = "API URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(url, str) or not self._validate_url(url):
            err_msg = (
                "Invalid API URL value provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate token
        token = configuration.get("token")
        if not token:
            log_msg = "API Token is an required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {log_msg}"
            )
            return ValidationResult(success=False, message=log_msg)
        elif not isinstance(token, str):
            err_msg = (
                "Invalid API Token provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Log Source Identifier
        log_source_identifier = configuration.get(
            "log_source_identifier", ""
        ).strip()
        if not log_source_identifier:
            err_msg = (
                "Log Source Identifier is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(log_source_identifier, str):
            err_msg = (
                "Invalid Log Source Identifier value provided"
                " in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate mappings
        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(
            mappings, dict
        ) or not huntress_hec_validator.validate_mappings(mappings):
            err_msg = (
                f"Invalid {PLATFORM_NAME} attribute mapping found in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth(
            url=url, token=token, log_source_identifier=log_source_identifier
        )
