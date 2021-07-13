const debug = require('@tryghost/debug')('web:oauth:app');
const {URL} = require('url');
const passport = require('passport');
const GitHubStrategy = require('passport-github-oauth20').Strategy;
const express = require('../../../shared/express');
const urlUtils = require('../../../shared/url-utils');
const shared = require('../shared');
const config = require('../../../shared/config');
const settingsCache = require('../../../shared/settings-cache');
const models = require('../../models');
const auth = require('../../services/auth');

function randomPassword() {
    return require('crypto').randomBytes(128).toString('hex');
}

module.exports = function setupOAuthApp() {
    debug('OAuth App setup start');
    const oauthApp = express('oauth');
    if (!config.get('enableDeveloperExperiments')) {
        debug('OAuth App setup skipped');
        return oauthApp;
    }

    // send 503 json response in case of maintenance
    oauthApp.use(shared.middlewares.maintenance);

    /**
     * Configure the passport.authenticate middleware
     * We need to configure it on each request because clientId and secret
     * will change (when the Owner is changing these settings)
     */
    function githubOAuthMiddleware(clientId, secret) {
        return (req, res, next) => {
            // TODO: use url config instead of the string /ghost

            //Create the callback url to be sent to GitHub
            const callbackUrl = new URL(urlUtils.getSiteUrl());
            callbackUrl.pathname = '/ghost/oauth/github/callback';

            passport.authenticate(new GitHubStrategy({
                clientID: clientId,
                clientSecret: secret,
                callbackURL: callbackUrl.href,
                allRawEmails: true
            }, async function (accessToken, refreshToken, profile) {
                // This is the verify function that checks that a GitHub-authenticated user
                // is matching one of our users (or invite).
                if (req.user) {
                    // CASE: the user already has an active Ghost session
                    const emails = profile.emails.filter(email => email.verified === true).map(email => email.value);

                    if (!emails.includes(req.user.get('email'))) {
                        return res.redirect('/ghost/#/staff/?message=oauth-linking-failed');
                    }

                    // TODO: configure the oauth data for this user (row in the oauth table)

                    //Associate logged-in user with oauth account
                    req.user.set('password', randomPassword());
                    await req.user.save();
                } else {
                    // CASE: the user is logging-in or accepting an invite
                    //Find user in DB and log-in
                    //TODO: instead find the oauth row with the email use the provider id
                    const emailRegex = new RegExp(settingsCache.get('github_email_pattern') ?? '.*@.*');
                    const emails = profile.emails.filter(email => email.verified === true);
                    if (emails.length < 1) {
                        return res.redirect('/ghost/#/signin?message=login-failed');
                    }
                    const email = emails.filter(mail => emailRegex.test(mail.value))[0].value ?? emails.filter(mail => mail.primary === true)[0].value ?? emails[0].value;

                    let user = await models.User.findOne({
                        email: email
                    });

                    if (!user) {
                        // CASE: the user is accepting an invite
                        // TODO: move this code in the invitations service
                        const options = {context: {internal: true}};
                        let invite = await models.Invite.findOne({email, status: 'sent'}, options);

                        if (!invite || invite.get('expires') < Date.now()) {
                            /*const octokit = new Octokit({ auth: accessToken });
                            const orgs = await octokit.request("GET /user/orgs");*/
                            const userInOrg = profile.orgs.some(org => org.login === settingsCache.get('github_org'));
                            if (!userInOrg) {
                                return res.redirect('/ghost/#/signin?message=login-failed');
                            }
                        }

                        //Accept invite
                        user = await models.User.add({
                            email: email,
                            name: profile.username,
                            password: randomPassword(),
                            roles: [invite?.toJSON()?.role_id ?? (await models.Role.findOne({name: 'Contributor'})).id]
                        }, options);
                        if (invite) {
                            await invite.destroy(options);
                        }
                        // TODO: create an oauth model link to user
                    }

                    req.user = user;
                }

                await auth.session.sessionService.createSessionForUser(req, res, req.user);

                return res.redirect('/ghost/');
            }), {
                scope: ['read:org', 'user:email', 'user'],
                session: false,
                prompt: 'consent',
                accessType: 'offline'
            })(req, res, next);
        };
    }

    oauthApp.get('/:provider', auth.authenticate.authenticateAdminApi, (req, res, next) => {
        if (req.params.provider !== 'github') {
            return res.sendStatus(404);
        }

        const clientId = settingsCache.get('oauth_client_id');
        const secret = settingsCache.get('oauth_client_secret');

        if (clientId && secret) {
            return githubOAuthMiddleware(clientId, secret)(req, res, next);
        }

        res.sendStatus(404);
    });

    oauthApp.get('/:provider/callback', (req, res, next) => {
        // Set the referrer as the ghost instance domain so that the session is linked to the ghost instance domain
        req.headers.referrer = urlUtils.getSiteUrl();
        next();
    }, auth.authenticate.authenticateAdminApi, (req, res, next) => {
        if (req.params.provider !== 'github') {
            return res.sendStatus(404);
        }

        const clientId = settingsCache.get('oauth_client_id');
        const secret = settingsCache.get('oauth_client_secret');

        if (clientId && secret) {
            return githubOAuthMiddleware(clientId, secret)(req, res, next);
        }

        res.sendStatus(404);
    });

    debug('OAuth App setup end');

    return oauthApp;
};
