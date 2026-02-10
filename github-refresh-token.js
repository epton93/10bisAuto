#!/usr/bin/env node

const utils = require('./github-actions-utils');

class GitHubTokenRefresh {
    constructor() {
        this.logFile = 'refresh.log';
    }

    /**
     * Extract tokens from response headers/cookies
     */
    async extractTokensFromHeaders(response) {
        const tokens = {};
        
        try {
            // Method 1: Check for tokens in Set-Cookie headers
            // Ensure we handle case insensitivity or missing headers safely
            const setCookieHeaders = response.headers['set-cookie'] || [];
            
            for (const cookie of setCookieHeaders) {
                // Improved Regex: Handles optional quotes and ensures cleaner extraction
                const authMatch = cookie.match(/Authorization=["']?([^;"']+)["']?/);
                if (authMatch) {
                    tokens.AccessToken = authMatch[1];
                    utils.maskValue(authMatch[1]);
                    await utils.log('AccessToken extracted from Set-Cookie header', this.logFile);
                }
                
                const refreshMatch = cookie.match(/RefreshToken=["']?([^;"']+)["']?/);
                if (refreshMatch) {
                    tokens.RefreshToken = refreshMatch[1];
                    utils.maskValue(refreshMatch[1]);
                    await utils.log('RefreshToken extracted from Set-Cookie header', this.logFile);
                }
            }
            
            // Method 2: Check for Authorization header
            if (response.headers['authorization']) {
                tokens.AccessToken = response.headers['authorization'].replace(/^Bearer\s+/i, '');
                utils.maskValue(tokens.AccessToken);
                await utils.log('AccessToken extracted from Authorization header', this.logFile);
            }
            
            // Method 3: Check for custom headers
            if (response.headers['x-access-token']) {
                tokens.AccessToken = response.headers['x-access-token'];
                utils.maskValue(tokens.AccessToken);
                await utils.log('AccessToken extracted from X-Access-Token header', this.logFile);
            }
            
            if (response.headers['x-refresh-token']) {
                tokens.RefreshToken = response.headers['x-refresh-token'];
                utils.maskValue(tokens.RefreshToken);
                await utils.log('RefreshToken extracted from X-Refresh-Token header', this.logFile);
            }
            
        } catch (error) {
            await utils.log(`Error extracting tokens from headers: ${error.message}`, this.logFile);
        }
        
        return tokens;
    }

    /**
     * Main function to refresh authentication tokens
     */
    async refreshTokens() {
        // REMOVED try/catch here to let errors bubble up to run()
        
        await utils.log('Starting token refresh process', this.logFile);
        
        // Read current configuration
        const config = utils.getConfig();
        
        // Log current token info (masked)
        const currentAccessToken = config.AccessToken || 'NOT_SET';
        const currentRefreshToken = config.RefreshToken || 'NOT_SET';
        
        // Safety check for substring lengths to prevent crash on short strings
        const safeLogToken = (t) => t.length > 20 ? `${t.substring(0, 10)}...${t.substring(t.length - 10)}` : '***';

        await utils.log(`Current AccessToken: ${safeLogToken(currentAccessToken)} (length: ${currentAccessToken.length})`, this.logFile);
        await utils.log(`Current RefreshToken: ${safeLogToken(currentRefreshToken)} (length: ${currentRefreshToken.length})`, this.logFile);
        
        // Validate required fields
        utils.validateConfig(config, ['RefreshToken']);
        
        // Mask sensitive values in memory
        utils.maskValue(config.AccessToken);
        utils.maskValue(config.RefreshToken);
        
        const requestOptions = {
            method: 'POST',
            url: 'https://api.10bis.co.il/api/v1/Authentication/RefreshToken',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Language': 'he',
                'X-App-Type': 'web',
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
            },
            data: {
                refreshToken: config.RefreshToken
            }
        };

        if (config.AccessToken && config.RefreshToken) {
            requestOptions.headers['Cookie'] = `Authorization=${config.AccessToken}; RefreshToken=${config.RefreshToken}`;
        }

        await utils.log('Making refresh token request to 10bis API', this.logFile);
        
        const response = await utils.makeHttpRequest(requestOptions);
        
        if (!response) {
            throw new Error('No response from refresh token API');
        }

        await utils.log(`Response status: ${response.status}`, this.logFile);
        
        // Extract new tokens from response headers/cookies
        const headerTokens = await this.extractTokensFromHeaders(response);
        
        // Check response body
        const bodyTokens = {};
        if (response.data) {
            if (response.data.AccessToken) {
                bodyTokens.AccessToken = response.data.AccessToken;
                utils.maskValue(response.data.AccessToken);
            }
            if (response.data.RefreshToken) {
                bodyTokens.RefreshToken = response.data.RefreshToken;
                utils.maskValue(response.data.RefreshToken);
            }
        }

        // Merge strategies: Only overwrite body tokens if header tokens are explicitly defined
        const updates = { ...bodyTokens };
        if (headerTokens.AccessToken) updates.AccessToken = headerTokens.AccessToken;
        if (headerTokens.RefreshToken) updates.RefreshToken = headerTokens.RefreshToken;

        // Update other fields
        if (response.data && response.data.Amount !== undefined) {
            updates.Amount = response.data.Amount;
        }

        // VALIDATION: Ensure we actually got tokens
        if (!updates.AccessToken && !updates.RefreshToken) {
            await utils.log(`Full response data: ${JSON.stringify(response.data || {}, null, 2)}`, this.logFile);
            throw new Error('API returned 200 OK but no tokens were found in headers or body.');
        }

        // Log changes
        if (updates.AccessToken && updates.AccessToken !== config.AccessToken) {
            await utils.log('AccessToken has been updated.', this.logFile);
        }
        
        if (updates.RefreshToken && updates.RefreshToken !== config.RefreshToken) {
            await utils.log('RefreshToken has been updated.', this.logFile);
        }

        // Persist updates
        await utils.updateConfig(updates);
        
        // GitHub Actions Outputs
        if (process.env.GITHUB_ACTIONS) {
            if (updates.AccessToken) await utils.setOutput('access_token', updates.AccessToken);
            if (updates.RefreshToken) await utils.setOutput('refresh_token', updates.RefreshToken);
            await utils.setOutput('tokens_updated', 'true');
        }
        
        await utils.log(`Token refresh completed. Updated: ${Object.keys(updates).join(', ')}`, this.logFile);
    }

    /**
     * Run the token refresh with proper error handling
     */
    async run() {
        try {
            await utils.log(`=== Token Refresh Started at ${utils.getCurrentTimeIsrael()} ===`, this.logFile);
            await this.refreshTokens();
            await utils.log(`=== Token Refresh Completed at ${utils.getCurrentTimeIsrael()} ===`, this.logFile);
            process.exit(0);
        } catch (error) {
            // Centralized error handling
            const errorMessage = `Token refresh failed: ${error.message}`;
            console.error(error); // Ensure it prints to console stderr
            
            await utils.log(errorMessage, 'error.log');
            await utils.log(errorMessage, this.logFile);
            
            if (process.env.GITHUB_ACTIONS) {
                await utils.setOutput('tokens_updated', 'false');
                await utils.setOutput('error', error.message);
            }
            
            await utils.log(`=== Token Refresh Failed at ${utils.getCurrentTimeIsrael()} ===`, this.logFile);
            process.exit(1);
        }
    }
}

// Run the script
if (require.main === module) {
    const tokenRefresh = new GitHubTokenRefresh();
    tokenRefresh.run();
}

module.exports = GitHubTokenRefresh;
