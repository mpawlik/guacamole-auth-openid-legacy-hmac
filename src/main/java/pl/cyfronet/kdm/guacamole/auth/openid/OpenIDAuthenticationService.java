package pl.cyfronet.kdm.guacamole.auth.openid;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.openid4java.OpenIDException;
import org.openid4java.association.AssociationException;
import org.openid4java.association.AssociationSessionType;
import org.openid4java.consumer.*;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.FetchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.cyfronet.kdm.guacamole.auth.openid.form.OpenIDField;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

public class OpenIDAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDAuthenticationService.class);


    private static ConsumerManager consumerManager;
    private final String openIdEndpoint;
    private final String returnToUrl;
    private final String realm;

    {
        logger.debug("Creating new ConsumerManagera");
        consumerManager = new ConsumerManager();
        consumerManager.setAssociations(new InMemoryConsumerAssociationStore());
        consumerManager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        consumerManager.setMinAssocSessEnc(AssociationSessionType.DH_SHA256);
    }


    public OpenIDAuthenticationService(HttpServletRequest request) throws GuacamoleException {

        //initialize parameters from properties
        Environment environment = new LocalEnvironment();

        openIdEndpoint = environment.getRequiredProperty(OpenIDAuthenticationProperties.OPENID_ENDPOINT);
        logger.debug("Setting openIdEndpoint to: {}", openIdEndpoint);
        returnToUrl = environment.getRequiredProperty(OpenIDAuthenticationProperties.OPENID_RETURNTOURL);
        logger.debug("Setting returnToUrl to: {}", returnToUrl);
        realm = environment.getRequiredProperty(OpenIDAuthenticationProperties.OPENID_REALM);
        logger.debug("Setting realm to: {}", realm);
    }

    public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
        logger.debug("Service authenticateUser()");
        //put openid code here, check for proper request if it's invalid throw exception

        HttpServletRequest httpServletRequest = credentials.getRequest();

        logger.debug("queryURL: {}", httpServletRequest.getRequestURI());
        logger.debug("queryString: {}", httpServletRequest.getQueryString());
        for (Enumeration e = httpServletRequest.getAttributeNames(); e.hasMoreElements(); ) {
            logger.debug("attribute: {}", e.nextElement());
        }
        logger.debug("parameterCount: {}", httpServletRequest.getParameterMap().keySet().size());

        for (Object keyObj : httpServletRequest.getParameterMap().keySet()) {
            String key = (String) keyObj;
            logger.debug("key: {}", key);
        }
        if (httpServletRequest.getParameter("openid.identity") != null) {
            logger.debug("authenticateUser(): handle reposnse");
            try {
                //handle incoming openid response

                ParameterList response = new ParameterList(httpServletRequest.getParameterMap());
                DiscoveryInformation discovered = (DiscoveryInformation) httpServletRequest.getSession().getAttribute("openid-disc");

                StringBuffer receivingURL = new StringBuffer(returnToUrl);
                String queryString = httpServletRequest.getQueryString();
                if (queryString != null && queryString.length() > 0)
                    receivingURL.append("?").append(httpServletRequest.getQueryString());

                VerificationResult verification = consumerManager.verify(receivingURL.toString(), response, discovered);

                Identifier verified = verification.getVerifiedId();
                logger.debug("finished with verification");
                if (verified != null) {
                    //success!
                    logger.debug("success");
                    logger.debug(verified.getIdentifier());
                    return null;
                }
            } catch (OpenIDException e) {
                e.printStackTrace();
            }

        } else {
            //place a request for new authentication action
            logger.debug("authenticateUser(): place auth request");
            List discoveries = null;
            try {
                discoveries = consumerManager.discover(openIdEndpoint);
                DiscoveryInformation discovered = consumerManager.associate(discoveries);

                httpServletRequest.getSession().setAttribute("openid-disc", discovered);

                AuthRequest authReq = consumerManager.authenticate(discovered, returnToUrl);
                authReq.setRealm(realm);

                String destinationUrl = authReq.getDestinationUrl(true);
                logger.debug("destinationURL: {}", destinationUrl);
                throw new GuacamoleInvalidCredentialsException("Invalid login",
                        new CredentialsInfo(Arrays.asList(new Field[]{
                                new OpenIDField(
                                        destinationUrl
                                )
                        }))
                );
            } catch (OpenIDException e) {
                e.printStackTrace();
            }

        }
        return null;
    }

}
