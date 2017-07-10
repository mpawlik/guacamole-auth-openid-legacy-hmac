package pl.cyfronet.kdm.guacamole.auth.openid;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;


public class OpenIDAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDAuthenticationProvider.class);

    public String getIdentifier() {
        return "guac-openid-legacy";
    }

    public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
        logger.debug("authenticateUser()");
        try {
            OpenIDAuthenticationService openIDAuthenticationService = new OpenIDAuthenticationService();
            return openIDAuthenticationService.authenticateUser(this, credentials);
        } catch (GuacamoleException e) {
            logger.error("Exception! {}", e);
            throw e;
        }
    }

    public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser, Credentials credentials) throws GuacamoleException {
        logger.debug("updateAuthenticatedUser()");
        return authenticatedUser;
    }

    public UserContext getUserContext(AuthenticatedUser authenticatedUser) throws GuacamoleException {
        logger.debug("getUserContext()");
        try {

            OpenIDAuthenticationService openIDAuthenticationService = new OpenIDAuthenticationService();
            return openIDAuthenticationService.getUserContext(this, authenticatedUser);
        } catch (GuacamoleException e) {
            logger.error("Exception! {}", e);
            throw e;
        }
    }

    public UserContext updateUserContext(UserContext userContext, AuthenticatedUser authenticatedUser, Credentials credentials) throws GuacamoleException {
        logger.debug("updateUserContext()");
        return userContext;
    }
}
