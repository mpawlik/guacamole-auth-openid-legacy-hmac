package pl.cyfronet.kdm.guacamole.auth.openid;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.environment.LocalEnvironment;
import org.glyptodon.guacamole.form.Field;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.credentials.CredentialsInfo;
import org.glyptodon.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
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
import java.util.List;
import java.util.Map;

public class OpenIDAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDAuthenticationService.class);
    public static final String FIELD_EMAIL_URI = "http://schema.openid.net/contact/email";
    public static final String FIELD_EMAIL_NAME = "email";


    private static ConsumerManager consumerManager;
    private final String openIdEndpoint;
    private final String returnToUrl;

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
    }

    public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
        logger.debug("Service authenticateUser()");
        //put openid code here, check for proper request if it's invalid throw exception

        HttpServletRequest httpServletRequest = credentials.getRequest();

        logger.debug("queryURL: {}", httpServletRequest.getRequestURI());
        logger.debug("parameterCount: {}", httpServletRequest.getParameterMap().keySet().size());

        for( Object keyObj : httpServletRequest.getParameterMap().keySet()) {
            String key = (String) keyObj;
            logger.debug("key: {}", key);
        }
        if (httpServletRequest.getParameter("openid.op_endpoint") != null) {
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

                FetchRequest fetch = FetchRequest.createFetchRequest();
                fetch.addAttribute(FIELD_EMAIL_NAME, FIELD_EMAIL_URI, true);

                AuthRequest authReq = consumerManager.authenticate(discovered, returnToUrl);
//                AuthRequest authReq = consumerManager.authenticate(discovered, returnToUrl + "?is_return=true");
                authReq.addExtension(fetch);

                String destinationUrl = authReq.getDestinationUrl(true);
                logger.debug("destinationURL: {}", destinationUrl);
                throw new GuacamoleInvalidCredentialsException("Invalid login",
                        new CredentialsInfo(Arrays.asList(new Field[]{
                                new OpenIDField(
                                        destinationUrl
                                )
                        }))
                );
            } catch (DiscoveryException e) {
                e.printStackTrace();
            } catch (ConsumerException e) {
                e.printStackTrace();
            } catch (MessageException e) {
                e.printStackTrace();
            }

        }
        throw new GuacamoleInvalidCredentialsException("Invalid login",
                new CredentialsInfo(Arrays.asList(new Field[]{
                        new OpenIDField(
                                "asd"
                        )
                }))
        );
//        return null;
    }

}
