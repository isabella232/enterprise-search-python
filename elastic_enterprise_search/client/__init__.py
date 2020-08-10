#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

import jwt
from six.moves.urllib.parse import urljoin, urlencode
from .app_search import AppSearch as _AppSearch
from .enterprise_search import EnterpriseSearch as _EnterpriseSearch
from .workplace_search import WorkplaceSearch as _WorkplaceSearch

__all__ = ["AppSearch", "EnterpriseSearch", "WorkplaceSearch"]


DEFAULT = object()


class AppSearch(_AppSearch):
    """Client for Elastic App Search service
    `<https://www.elastic.co/guide/en/app-search/current/api-reference.html>`_
    """

    @staticmethod
    def create_signed_search_key(
        api_key,
        api_key_name,
        search_fields=DEFAULT,
        result_fields=DEFAULT,
        filters=DEFAULT,
        facets=DEFAULT,
    ):
        """Creates a Signed Search Key to keep your Private API Key secret
        and restrict what a user can search over.

        `<https://www.elastic.co/guide/en/app-search/current/authentication.html#authentication-signed>`_

        :arg api_key: Private API Key
        :arg api_key_name: Name of the Signed Search Key
        :arg search_fields: Fields to search over.
        :arg result_fields: Fields to return in the result
        :arg filters: Adds filters to the search requests
        :arg facets: Sets the facets that are allowed.
            To disable aggregations set to '{}' or 'None'.
        """
        options = {
            k: v
            for k, v in (
                ("api_key_name", api_key_name),
                ("search_fields", search_fields),
                ("result_fields", result_fields),
                ("filters", filters),
                ("facets", facets),
            )
            if v is not DEFAULT
        }
        return jwt.encode(
            payload=options, key=api_key.encode(), algorithm="HS256"
        ).decode()


class WorkplaceSearch(_WorkplaceSearch):
    """Client for Workplace Search
    `<https://www.elastic.co/guide/en/workplace-search/current/workplace-search-api-overview.html>`_
    """

    def oauth_authorize(self, response_type, client_id, redirect_uri):
        """Create a URL to redirect the requesting user to start the OAuth
        flow. This is the starting point for either the 'Confidential' flow
        or the 'Implicit' flow.

        :arg response_type: 'code' for confidential flow, 'token' for implicit flow
        :arg client_id: Client ID as generated when setting up the OAuth Application
        :arg redirect_uri: Location to redirect the user once the OAuth process is completed.
            This value must match one of the URIs configured within the OAuth Application.
        :returns: URL to send to the user via a 3XX HTTP status
        """
        if response_type not in ("token", "code"):
            raise ValueError(
                "'response_type' must be either 'code' for confidential flow or 'token' for implicit flow"
            )
        if not all((client_id, response_type, redirect_uri)):
            raise TypeError(
                "'client_id', 'response_type' and 'redirect_uri' must all be non-empty strings"
            )
        if not all(
            isinstance(param, str) for param in (client_id, response_type, redirect_uri)
        ):
            raise ValueError(
                "'client_id', 'response_type' and 'redirect_uri' must all be non-empty strings"
            )

        query_params = urlencode(
            {
                "response_type": response_type,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            }
        )
        return urljoin(self.transport.base_url, "/ws/oauth/authorize?%s" % query_params)

    def oauth_exchange_access_token(self, client_id, client_secret, redirect_uri, code):
        """Exchanges a code received from the authorization step
        of a Confidential OAuth flow for an access token. The code
        is received from the application at the 'redirect_uri' endpoint.

        Returns the HTTP response that has a JSON body with the following:

         .. code-block: json
            {
                "access_token": "8b596f23e0b989178973bf3e329176e149a80ec5a7fb333e0167c4774c85744e",
                "token_type": "Bearer",
                "expires_in": 7200,
                "refresh_token": "43b760ef339bcae955109e5a77dc0784e288047c776df6cf92279620a65d829a",
                "scope": "search"
            }

        :arg client_id: Client ID as generated when setting up the OAuth Application
        :arg client_secret: Client Secret as generated when setting up the OAuth Application
        :arg redirect_uri: Location to redirect the user once the OAuth process is completed.
            This value must match one of the URIs configured within the OAuth Application.
        :arg code: Authorization code returned by the /authorize endpoint
        :returns:
        """
        if not all((client_id, client_secret, redirect_uri, code)):
            raise TypeError(
                "'client_id', 'client_secret', 'redirect_uri', and 'code' must all be non-empty strings"
            )
        if not all(
            isinstance(param, str)
            for param in (client_id, client_secret, redirect_uri, code)
        ):
            raise ValueError(
                "'client_id', 'client_secret', 'redirect_uri', and 'code' must all be non-empty strings"
            )

        return self.transport.request(
            method="POST",
            path="/ws/oauth/token",
            params={
                "grant_type": "authorization_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code": code,
            },
            headers={"authorization": None},
        )

    def oauth_refresh_access_token(
        self, client_id, client_secret, redirect_uri, access_token, refresh_token
    ):
        """Exchanges a code received from the authorization step
        of a Confidential OAuth flow for an access token. The code
        is received from the application at the 'redirect_uri' endpoint.

        Returns the HTTP response that has a JSON body with the following:

         .. code-block: json
            {
                "access_token": "8b596f23e0b989178973bf3e329176e149a80ec5a7fb333e0167c4774c85744e",
                "token_type": "Bearer",
                "expires_in": 7200,
                "refresh_token": "43b760ef339bcae955109e5a77dc0784e288047c776df6cf92279620a65d829a",
                "scope": "search"
            }

        :arg client_id: Client ID as generated when setting up the OAuth Application
        :arg client_secret: Client Secret as generated when setting up the OAuth Application
        :arg redirect_uri: Location to redirect the user once the OAuth process is completed.
            This value must match one of the URIs configured within the OAuth Application.
        :arg access_token:
        :arg refresh_token:
        :returns:
        """
        if not all(
            (client_id, client_secret, redirect_uri, access_token, refresh_token)
        ):
            raise TypeError(
                "'client_id', 'client_secret', 'redirect_uri', and 'code' must all be non-empty strings"
            )
        if not all(
            isinstance(param, str)
            for param in (
                client_id,
                client_secret,
                redirect_uri,
                access_token,
                refresh_token,
            )
        ):
            raise ValueError(
                "'client_id', 'client_secret', 'redirect_uri', and 'code' must all be non-empty strings"
            )

        return self.transport.request(
            method="POST",
            path="/ws/oauth/token",
            params={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "refresh_token": refresh_token,
            },
            headers={"authorization": "Bearer %s" % access_token},
        )


class EnterpriseSearch(_EnterpriseSearch):
    """Client for Enterprise Search"""

    def __init__(self, transport_class=None, **kwargs):
        super(EnterpriseSearch, self).__init__(
            transport_class=transport_class, **kwargs
        )

        self.app_search = AppSearch(_transport=self.transport.copy())
        self.workplace_search = WorkplaceSearch(_transport=self.transport.copy())
