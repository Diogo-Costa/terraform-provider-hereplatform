package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

var _ provider.Provider = (*hereProvider)(nil)

type hereProvider struct {
	version string
	opts    options
}

type options struct {
	httpClient *http.Client
	retry      client.RetryPolicy
	poll       client.PollPolicy
	getenv     func(string) string
}

// Option customises the provider, mainly so tests can target a fake HERE API.
type Option func(*options)

// WithHTTPClient replaces the HTTP client used for token and API requests.
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.httpClient = c } }

// WithRetryPolicy overrides the transport retry policy.
func WithRetryPolicy(p client.RetryPolicy) Option { return func(o *options) { o.retry = p } }

// WithPollPolicy overrides the read-after-write polling policy.
func WithPollPolicy(p client.PollPolicy) Option { return func(o *options) { o.poll = p } }

// WithEnv replaces os.Getenv when resolving HERE_* environment variables.
func WithEnv(getenv func(string) string) Option { return func(o *options) { o.getenv = getenv } }

// New returns a constructor for the HERE platform provider.
func New(version string, opts ...Option) func() provider.Provider {
	return func() provider.Provider {
		p := &hereProvider{version: version}
		for _, o := range opts {
			o(&p.opts)
		}
		return p
	}
}

type providerModel struct {
	ClientID        types.String `tfsdk:"client_id"`
	PrivateKey      types.String `tfsdk:"private_key"`
	KeyID           types.String `tfsdk:"key_id"`
	AccessKeyID     types.String `tfsdk:"access_key_id"`
	AccessKeySecret types.String `tfsdk:"access_key_secret"`
	CredentialsFile types.String `tfsdk:"credentials_file"`
	TokenURL        types.String `tfsdk:"token_url"`
	APIURL          types.String `tfsdk:"api_url"`
}

func (p *hereProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "hereplatform"
	resp.Version = p.version
}

func (p *hereProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages HERE platform identity and access management: apps, API keys and trusted domains.",
		Attributes: map[string]schema.Attribute{
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Client ID of the HERE app the provider authenticates as with OAuth 2.1 " +
					"`private_key_jwt`. Defaults to `" + envClientID + "`, then to `here.client.id` in `credentials_file`.",
				Optional: true,
			},
			"private_key": schema.StringAttribute{
				MarkdownDescription: "PEM-encoded RSA private key (PKCS #1 or PKCS #8, at least 2048 bits) matching a JWK " +
					"registered on the app. Defaults to `" + envPrivateKey + "`.",
				Optional:  true,
				Sensitive: true,
			},
			"key_id": schema.StringAttribute{
				MarkdownDescription: "`kid` of the registered JWK, sent in the client assertion header. Optional but " +
					"recommended by HERE. Defaults to `" + envKeyID + "`.",
				Optional: true,
			},
			"access_key_id": schema.StringAttribute{
				MarkdownDescription: "Access key ID for OAuth 1.0 client authentication. Defaults to `" + envAccessKeyID +
					"`, then to `here.access.key.id` in `credentials_file`.",
				Optional: true,
			},
			"access_key_secret": schema.StringAttribute{
				MarkdownDescription: "Access key secret for OAuth 1.0 client authentication. Defaults to `" +
					envAccessKeySecret + "`, then to `here.access.key.secret` in `credentials_file`.",
				Optional:  true,
				Sensitive: true,
			},
			"credentials_file": schema.StringAttribute{
				MarkdownDescription: "Path to a HERE `credentials.properties` file. Defaults to `" + envCredentialsFile + "`.",
				Optional:            true,
			},
			"token_url": schema.StringAttribute{
				MarkdownDescription: "OAuth token endpoint. Defaults to `" + envTokenURL + "`, then to " +
					"`here.token.endpoint.url` in `credentials_file`, then to `" + client.DefaultTokenURL + "`.",
				Optional: true,
			},
			"api_url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the HERE Authentication API v1.1. Defaults to `" + envAPIURL +
					"`, then to `" + client.DefaultAPIURL + "`.",
				Optional: true,
			},
		},
	}
}

func (p *hereProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var model providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg, diags := resolveConfig(model, p.opts.getenv)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg.HTTPClient = p.opts.httpClient
	cfg.Retry = p.opts.retry
	cfg.Poll = p.opts.poll
	cfg.UserAgent = "terraform-provider-hereplatform/" + p.version

	c, err := client.New(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create the HERE API client", err.Error())
		return
	}
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *hereProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newAppResource,
		newAppAPIKeyResource,
		newAppTrustedDomainsResource,
	}
}

func (p *hereProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newAppDataSource,
	}
}
