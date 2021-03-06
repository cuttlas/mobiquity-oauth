<?php namespace LucaDegasperi\OAuth2Server;

use Illuminate\Support\ServiceProvider;
use LucaDegasperi\OAuth2Server\Proxies\AuthorizationServerProxy;
use LucaDegasperi\OAuth2Server\Filters\OAuthFilter;
use LucaDegasperi\OAuth2Server\Repositories\FluentClient;
use LucaDegasperi\OAuth2Server\Repositories\FluentScope;
use LucaDegasperi\OAuth2Server\Util\LaravelRequest;

class OAuth2ServerServiceProvider extends ServiceProvider
{

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package('lucadegasperi/oauth2-server-laravel', 'oauth2-server-laravel');

        require_once __DIR__.'/../../filters.php';
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerRepositoryBindings();

        $this->registerInterfaceBindings();

        $this->registerAuthorizationServer();
        
        $this->registerResourceServer();

        $this->registerFilterBindings();
        
        $this->registerExpiredTokensCommand();
    }

    /**
     * Bind the repositories to the IoC container
     * @return void
     */
    public function registerRepositoryBindings()
    {
        $app = $this->app;

        $app->bind('LucaDegasperi\OAuth2Server\Repositories\FluentClient', function ($app) {

            $limitClientsToGrants = $app['config']->get('oauth2-server-laravel::oauth2.limit_clients_to_grants');
            return new FluentClient($limitClientsToGrants);
        });

        $app->bind('LucaDegasperi\OAuth2Server\Repositories\FluentScope', function ($app) {

            $limitClientsToScopes = $app['config']->get('oauth2-server-laravel::oauth2.limit_clients_to_scopes');
            $limitScopesToGrants = $app['config']->get('oauth2-server-laravel::oauth2.limit_scopes_to_grants');

            return new FluentScope($limitClientsToScopes, $limitScopesToGrants);
        });
    }

    /**
     * Bind the interfaces to their implementations
     * @return void
     */
    public function registerInterfaceBindings()
    {
        $app = $this->app;

        $app->bind('League\OAuth2\Server\Storage\ClientInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentClient');
        $app->bind('League\OAuth2\Server\Storage\ScopeInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentScope');
        $app->bind('League\OAuth2\Server\Storage\SessionInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentSession');
        $app->bind('LucaDegasperi\OAuth2Server\Repositories\SessionManagementInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentSession');
    }

    /**
     * Register the Authorization server with the IoC container
     * @return void
     */
    public function registerAuthorizationServer()
    {
        $app = $this->app;

        $app['oauth2.authorization-server'] = $app->share(function ($app) {

            $server = $app->make('League\OAuth2\Server\Authorization');

            $config = $app['config']->get('oauth2-server-laravel::oauth2');

            // add the supported grant types to the authorization server
            foreach ($config['grant_types'] as $grantKey => $grantValue) {

                $server->addGrantType(new $grantValue['class']);
                $server->getGrantType($grantKey)->setAccessTokenTTL($grantValue['access_token_ttl']);

                if (array_key_exists('callback', $grantValue)) {
                    $server->getGrantType($grantKey)->setVerifyCredentialsCallback($grantValue['callback']);
                }
                if (array_key_exists('auth_token_ttl', $grantValue)) {
                    $server->getGrantType($grantKey)->setAuthTokenTTL($grantValue['auth_token_ttl']);
                }
                if (array_key_exists('refresh_token_ttl', $grantValue)) {
                    $server->getGrantType($grantKey)->setRefreshTokenTTL($grantValue['refresh_token_ttl']);
                }
                if (array_key_exists('rotate_refresh_tokens', $grantValue)) {
                    $server->getGrantType($grantKey)->rotateRefreshTokens($grantValue['rotate_refresh_tokens']);
                }
            }

            $server->requireStateParam($config['state_param']);

            $server->requireScopeParam($config['scope_param']);

            $server->setScopeDelimeter($config['scope_delimiter']);

            $server->setDefaultScope($config['default_scope']);

            $server->setAccessTokenTTL($config['access_token_ttl']);

            $server->setRequest(new LaravelRequest());

            return new AuthorizationServerProxy($server);

        });
    }

    /**
     * Register the ResourceServer with the IoC container
     * @return void
     */
    public function registerResourceServer()
    {
        $app = $this->app;

        $app['oauth2.resource-server'] = $app->share(function ($app) {

            $server = $app->make('League\OAuth2\Server\Resource');

            $server->setRequest(new LaravelRequest());

            return $server;

        });
    }

    /**
     * Register the Filters to the IoC container because some filters need additional parameters
     * @return void
     */
    public function registerFilterBindings()
    {
        $app = $this->app;

        $app->bind('LucaDegasperi\OAuth2Server\Filters\OAuthFilter', function ($app) {
            $httpHeadersOnly = $app['config']->get('oauth2-server-laravel::oauth2.http_headers_only');

            return new OAuthFilter($httpHeadersOnly);
        });
    }

    /**
     * Register the expired token commands to artisan
     * 
     * @return void
     * @codeCoverageIgnore
     */
    public function registerExpiredTokensCommand()
    {
        $app = $this->app;

        $app['oauth2.expired-tokens-command'] = $app->share(function ($app) {
            return $app->make('LucaDegasperi\OAuth2Server\Commands\ExpiredTokensCommand');
        });

        $this->commands('oauth2.expired-tokens-command');
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     * @codeCoverageIgnore
     */
    public function provides()
    {

        return array('oauth2.authorization-server', 'oauth2.resource-server');
    }
}
