package pl.cyfronet.kdm.guacamole.auth.openid;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.form.Field;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.credentials.CredentialsInfo;
import org.glyptodon.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.cyfronet.kdm.guacamole.auth.openid.form.OpenIDField;

import java.util.Arrays;

public class OpenIDAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(OpenIDAuthenticationService.class);

    public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {

        throw new GuacamoleInvalidCredentialsException("Invalid login",
                new CredentialsInfo(Arrays.asList(new Field[]{
                        new OpenIDField(
                                "https://openid.plgrid.pl"
                        )
                }))
        );

    }

}
