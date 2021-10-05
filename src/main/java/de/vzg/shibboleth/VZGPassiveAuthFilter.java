/*
 * This file is part of ***  M y C o R e  ***
 * See http://www.mycore.de/ for details.
 *
 * MyCoRe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MyCoRe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MyCoRe.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.vzg.shibboleth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.MCRSessionMgr;
import org.mycore.common.MCRSystemUserInformation;
import org.mycore.common.MCRUserInformation;
import org.mycore.frontend.MCRFrontendUtil;
import org.mycore.frontend.servlets.MCRServlet;
import org.mycore.user2.MCRRealmFactory;
import org.mycore.user2.MCRUser;
import org.mycore.user2.MCRUserAttributeMapper;
import org.mycore.user2.MCRUserManager;
import org.mycore.user2.login.MCRShibbolethLoginServlet;
import org.mycore.user2.login.MCRShibbolethUserInformation;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mycore.backend.jpa.dnbtransfer.MCRDNBTRANSFERRESULTS_.objectId;

public class VZGPassiveAuthFilter implements Filter {

    private static final Logger LOGGER = LogManager.getLogger(MCRShibbolethLoginServlet.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
        throws IOException, ServletException {
        try {
            if (servletRequest instanceof HttpServletRequest && servletResponse instanceof HttpServletResponse) {
                LOGGER.debug("Passive auth filter running!");
                HttpServletRequest req = (HttpServletRequest) servletRequest;
                HttpServletResponse resp = (HttpServletResponse) servletResponse;

                String uid = (String) req.getAttribute("uid");
                String userId = uid != null ? uid : req.getRemoteUser();

                LOGGER.debug("User is is :" + userId);

                if (userId != null) {
                    final String realmId = userId.contains("@") ? userId.substring(userId.indexOf("@") + 1) : null;
                    if (realmId != null && MCRRealmFactory.getRealm(realmId) != null) {
                        try {
                            MCRServlet.initializeMCRSession(req, getClass().getName());
                            MCRFrontendUtil.configureSession(MCRSessionMgr.getCurrentSession(), req, resp);

                            if (MCRSessionMgr.getCurrentSession().getUserInformation().getUserID()
                                .equals(MCRSystemUserInformation.getGuestInstance().getUserID())) {

                                userId = userId.replace("@" + realmId, "");

                                final Map<String, Object> attributes = new HashMap<>();

                                final MCRUserAttributeMapper attributeMapper = MCRRealmFactory
                                    .getAttributeMapper(realmId);
                                for (final String key : attributeMapper.getAttributeNames()) {
                                    final Object value = req.getAttribute(key);
                                    if (value != null) {
                                        LOGGER.info("received {}:{}", key, value);
                                        attributes.put(key, value);
                                    }
                                }

                                MCRUserInformation userinfo;
                                MCRUser user = MCRUserManager.getUser(userId, realmId);
                                if (user != null) {
                                    LOGGER.info("login existing user \"{}\"", user.getUserID());

                                    attributeMapper.mapAttributes(user, attributes);
                                    user.setLastLogin();
                                    MCRUserManager.updateUser(user);

                                    userinfo = user;
                                } else {
                                    userinfo = new MCRShibbolethUserInformation(userId, realmId, attributes);
                                }

                                MCRSessionMgr.getCurrentSession().setUserInformation(userinfo);
                                // MCR-1154
                                req.changeSessionId();
                            }
                        } catch (Exception e) {
                            LOGGER.debug("Error while passive login!", e);
                            if (MCRSessionMgr.hasCurrentSession()) {
                                MCRSessionMgr.getCurrentSession().rollbackTransaction();
                            }
                        } finally {
                            MCRServlet.cleanupMCRSession(req, getClass().getName());
                            req.removeAttribute("currentThreadName");
                            req.removeAttribute("currentServletName");
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error while passive auth", e);
        } finally {
            filterChain.doFilter(servletRequest, servletResponse);
        }

    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
