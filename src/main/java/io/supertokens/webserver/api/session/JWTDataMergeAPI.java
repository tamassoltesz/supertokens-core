/*
 *    Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
 *
 *    This software is licensed under the Apache License, Version 2.0 (the
 *    "License") as published by the Apache Software Foundation.
 *
 *    You may not use this file except in compliance with the License. You may
 *    obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */

package io.supertokens.webserver.api.session;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.exceptions.AccessTokenPayloadError;
import io.supertokens.exceptions.UnauthorisedException;
import io.supertokens.output.Logging;
import io.supertokens.pluginInterface.RECIPE_ID;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.multitenancy.AppIdentifier;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.multitenancy.exceptions.TenantOrAppNotFoundException;
import io.supertokens.pluginInterface.session.SessionInfo;
import io.supertokens.session.Session;
import io.supertokens.session.accessToken.AccessToken;
import io.supertokens.storageLayer.StorageLayer;
import io.supertokens.utils.SemVer;
import io.supertokens.utils.Utils;
import io.supertokens.webserver.InputParser;
import io.supertokens.webserver.WebserverAPI;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

public class JWTDataMergeAPI extends WebserverAPI {

    /*
    * steps to make in one step:
    * FE calls for sessionInfo GET /recipe/session
    * Core returns sessionInfo with userDataInJWT in it to FE
    * FE removes the protected keys from it
    * FE overwrites the keys which is a param for FE (accessTokenPayloadUpdate)
    * FE removes the null valued keys from the newAccessTokenPayload
    * FE calls updateAccessTokenPayload PUT /recipe/jwt/data
    * CORE updates the sessionData in DB (after checks)
    *
    * So what we need is an API endpoint, which accepts the playloadUpdate data, queries the stored
    * session data. Merges the stored and the update, saves the merged into DB then returns the merged result to the caller
    *
    * */

    public JWTDataMergeAPI(Main main, String recipeId) {
        super(main,  RECIPE_ID.SESSION.toString());
    }

    @Override
    public String getPath() {
        return "/recipe/jwt/datamerge";
    }

    @Override
    protected void doPut (HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        JsonObject input = InputParser.parseJsonObjectOrThrowError(req);

        String sessionHandle = InputParser.parseStringOrThrowError(input, "sessionHandle", false);
        assert sessionHandle != null;

        JsonObject incomingUserDataInJWT = InputParser.parseJsonObjectOrThrowError(input, "userDataInJWT", false);
        assert incomingUserDataInJWT != null;

        TenantIdentifier tenantIdentifier;
        Storage storage;
        try {
            AppIdentifier appIdentifier = getAppIdentifier(req);
            tenantIdentifier = new TenantIdentifier(appIdentifier.getConnectionUriDomain(), appIdentifier.getAppId(),
                    Session.getTenantIdFromSessionHandle(sessionHandle));
            storage = StorageLayer.getStorage(tenantIdentifier, main);
        } catch (TenantOrAppNotFoundException e) {
            throw new ServletException(e);
        }

        try {
            SessionInfo storedSessionInfo = Session.getSession(tenantIdentifier, storage, sessionHandle);
            JsonObject storedUserDataInJWT = storedSessionInfo.userDataInJWT; // can be empty!

            JsonObject mergedUserData = mergeUserData(storedUserDataInJWT, incomingUserDataInJWT);

           if (getVersionFromRequest(req).greaterThanOrEqualTo(SemVer.v2_21)) {
                AccessToken.VERSION version = AccessToken.getAccessTokenVersionForCDI(getVersionFromRequest(req));
                Session.updateSession(tenantIdentifier, storage, sessionHandle, null,
                        mergedUserData, version);
            } else {
                Session.updateSessionBeforeCDI2_21(tenantIdentifier, storage, sessionHandle,
                        null, mergedUserData);
            }

            JsonObject result = new JsonObject();

            result.addProperty("status", "OK");
            super.sendJsonResponse(200, result, resp);

        } catch (StorageQueryException e) {
            throw new ServletException(e);
        } catch (AccessTokenPayloadError e) {
            throw new ServletException(new BadRequestException(e.getMessage()));
        } catch (UnauthorisedException e) {
            Logging.debug(main, tenantIdentifier, Utils.exceptionStacktraceToString(e));
            JsonObject reply = new JsonObject();
            reply.addProperty("status", "UNAUTHORISED");
            reply.addProperty("message", e.getMessage());
            super.sendJsonResponse(200, reply, resp);
        }
    }

    private JsonObject mergeUserData(JsonObject storedData, JsonObject incomingData){
        JsonObject merged = new JsonObject();
        Set<Map.Entry<String, JsonElement>> allEntries = storedData.entrySet();
        allEntries.addAll(incomingData.entrySet());
        for(Map.Entry<String, JsonElement> entry : allEntries){
            String key = entry.getKey();

            if (!incomingData.has(key)){
                merged.add(key, storedData.get(key));
            } else if(incomingData.get(key) != null){
                merged.add(key, incomingData.get(key));
            }
        }

        return merged;
    }

}
