/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.custom.authenticator.local;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.common.LoginIdentifier;
import org.wso2.custom.authenticator.local.internal.BasicCustomAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.wso2.custom.authenticator.local.BasicCustomAuthenticatorConstants.*;

/**
 * Username Password based custom Authenticator
 */
public class BasicCustomAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);


    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                HttpServletResponse response,
                                                AuthenticationContext context)
            throws AuthenticationFailedException {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();//This is the
        // default WSO2 IS login page. If you can create your custom login page you can use
        // that instead.
        String queryParams =
                FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(),
                        context.getContextIdentifier());

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) +
                    "&authenticators=BasicAuthenticator:" + "LOCAL" + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

     /**
     * This method is used to process the authentication response     
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicCustomAuthenticatorConstants.PASSWORD);

        Optional<org.wso2.carbon.user.core.common.User> user = Optional.empty();

        boolean isAuthenticated = false;

        // Check the authentication.
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = BasicCustomAuthenticatorServiceComponent.getRealmService()
                    .getTenantUserRealm(tenantId);
            if (userRealm != null) {
                UniqueIDUserStoreManager userStoreManager = (UniqueIDUserStoreManager) userRealm.getUserStoreManager();

                // This custom local authenticator is using the mobile as the username.
                // Therefore, the login identifier claim is http://wso2.org/claims/mobile.
//                AuthenticationResult authenticationResult1 = userStoreManager.
//                        authenticateWithID(MOBILE_CLAIM_URL, username, password, UserCoreConstants.DEFAULT_PROFILE);

//                String userid = "";
//                AuthenticationResult authenticationResult1 = userStoreManager.
//                        authenticateWithID(userid, password);
//
                List<LoginIdentifier> loginIdentifiersList = getLoginIdentifiers(username);
                AuthenticationResult authenticationResult = userStoreManager.
                        authenticateWithID(loginIdentifiersList,"CUSTOM", password);

                if (AuthenticationResult.AuthenticationStatus.SUCCESS == authenticationResult.getAuthenticationStatus()) {
                    user = authenticationResult.getAuthenticatedUser();
                    isAuthenticated = true;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Custom authentication failed since the user realm for the given tenant, " +
                            tenantId + " is null.");
                }
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " + tenantId,
                        User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("Custom authentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Custom authentication failed while trying to authenticate the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        // If the authentication fails, throws the invalid client credential exception.
        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(username));
        }

        // When the user is successfully authenticated, add the user to the authentication context to be used later in
        // the process.
        if (user.isPresent()) {
            username = user.get().getUsername();
            context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        }

    }

    private static List<LoginIdentifier> getLoginIdentifiers(String username) {

        List<LoginIdentifier> loginIdentifiersList = new ArrayList<>();

        LoginIdentifier loginID = new LoginIdentifier(USERNAME_CLAIM_URL, username,
                UserCoreConstants.DEFAULT_PROFILE, LoginIdentifier.LoginIdentifierType.CLAIM_URI);
        LoginIdentifier loginID2 = new LoginIdentifier(EMAIL_CLAIM_URL, username,
                UserCoreConstants.DEFAULT_PROFILE, LoginIdentifier.LoginIdentifierType.CLAIM_URI);
        loginIdentifiersList.add(loginID);
        loginIdentifiersList.add(loginID2);
        return loginIdentifiersList;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getFriendlyName() {
        //Set the name to be displayed in local authenticator drop down lsit
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        String userName = httpServletRequest.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
        String password = httpServletRequest.getParameter(BasicCustomAuthenticatorConstants.PASSWORD);

        log.info("--------------- BasicCustomAuthenticator: username is " + userName + " -----------------------");
        log.info("--------------- BasicCustomAuthenticator: password is " + password + " -----------------------");

        return userName != null && password != null;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    public AuthenticatedUser createTemporaryUser(String username){
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();

        authenticatedUser.setUserName(username);
        authenticatedUser.setAuthenticatedSubjectIdentifier("External API");
        return authenticatedUser;
    }
}