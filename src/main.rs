use std::path::PathBuf;
use eyre::WrapErr;
use eyre::ContextCompat;
use std::sync::Arc;
use core::time::Duration;
use std::str::FromStr;
use std::ffi::OsStr;
use eyre::Result;
use tap::prelude::*;

#[derive(Clone)]
pub struct DirectoryUrls {
	pub staging: Option<String>,
	pub production: String,
}
pub enum DirectoryConfig {
	LetsEncrypt,
	Other(String),
}
impl DirectoryConfig {
	pub fn urls(&self) -> DirectoryUrls {
		match self {
			Self::LetsEncrypt => DirectoryUrls {
				staging: Some("https://acme-staging-v02.api.letsencrypt.org/directory".to_string()),
				production: "https://acme-v02.api.letsencrypt.org/directory".to_string()
			},
			Self::Other(url) => DirectoryUrls {
				staging: Some(url.clone()),
				production: url.clone(),
			},
		}
	}
	pub async fn staging(&self) -> Result<Option<Arc<acme2::Directory>>> {
		if let Some(url) = self.urls().staging {
			Ok(Some(acme2::DirectoryBuilder::new(url).build().await?))
		} else {
			Ok(None)
		}
	}
	pub async fn production(&self) -> Result<Arc<acme2::Directory>> {
		Ok(acme2::DirectoryBuilder::new(self.urls().production).build().await?)
	}
}
impl FromStr for DirectoryConfig {
	type Err = eyre::Error;

	fn from_str(s: &str) -> Result<Self> {
		match s {
			"letsencrypt" => Ok(Self::LetsEncrypt),
			_ => Err(eyre::eyre!("Parsing of 'other' directories not yet implemented")),
		}
	}
}
impl Default for DirectoryConfig {
	fn default() -> Self {
		Self::LetsEncrypt
	}
}

struct CertificateConfig {
	watch_path: PathBuf,
	base_name: String,
	wildcard: bool,
	additional_names: Vec<String>,
	pubkeys: Vec<openssl::pkey::PKeyRef<openssl::pkey::Public>>,
}
impl CertificateConfig {
	fn from_directory(watch_path: PathBuf) -> Result<Self> {
		let base_name = watch_path.file_name().and_then(OsStr::to_str).context("no directory name in watch path")?.to_string();
		// TODO: validate that the path is a proper domain name
		let config_file_path = watch_path.join("certificate.yaml");
		if config_file_path.is_file() {
			todo!("Implement reading config file")
		} else {
			println!("Using defaults for certificate watch {}: wildcard cert for {} with no additional names", watch_path.to_string_lossy(), base_name);
			CertificateConfig {
				watch_path,
				base_name,
				wildcard: true,
				additional_names: vec![],
				pubkeys: vec![],
			}.pipe(Ok)
		}
	}

	fn start_order(&self, account: &Arc<acme2::Account>) -> Result<acme2::OrderBuilder> {
	    let mut order = acme2::OrderBuilder::new(account.clone());
	    if self.wildcard {
		    order.add_dns_identifier(format!("*.{}", self.base_name));
		} else {
			order.add_dns_identifier(self.base_name.clone());
		}
		for sub in &self.additional_names {
			order.add_dns_identifier(format!("{}.{}", sub, self.base_name));
		}
	    Ok(order)
	}

	async fn validate(&self, listen_address: std::net::SocketAddr, timeout: Duration, authorizations: Vec<acme2::Authorization>) -> Result<()> {
	  	for auth in authorizations {
	    	let challenge = auth.get_challenge("dns-01").context("DNS challenge")?;
	    	let challenge_token = challenge.token.as_ref().context("Challenge Token")?.clone();
	    	println!("challenge: {:?}", challenge_token);

			let socket = tokio::net::UdpSocket::bind(listen_address).await?;
			let authorization_handler = AuthorizationHandler { base_name: self.base_name.clone(), challenge_token };
	    	let mut dns_server = trust_dns_server::server::ServerFuture::new(authorization_handler);
	    	dns_server.register_socket(socket);

	    	let challenge = challenge.validate().await?;

		    // Poll the challenge every 5 seconds until it is in either the
		    // `valid` or `invalid` state.
		    let challenge = challenge.wait_done(timeout, 3).await?;

		    eyre::ensure!(challenge.status == acme2::ChallengeStatus::Valid, "DNS-based challenge failed");

		    // You can now remove the challenge file hosted on your webserver.

		    // Poll the authorization every 5 seconds until it is in either the
		    // `valid` or `invalid` state.
		    let authorization = auth.wait_done(timeout, 3).await?;
		    eyre::ensure!(authorization.status == acme2::AuthorizationStatus::Valid, "DNS-based challenge failed as not-authorized");
	    }
	    Ok(())
	}
}
impl FromStr for CertificateConfig {
	type Err = eyre::Error;

	fn from_str(s: &str) -> Result<Self> {
		let watch_path = PathBuf::from_str(s)?.canonicalize()?;
		if watch_path.is_dir() {
			Self::from_directory(watch_path)
		} else {
			Err(eyre::eyre!("certificate path '{}' is not a directory!", watch_path.to_string_lossy()))
		}
	}
}

#[derive(argh::FromArgs)]
/// Perform acme validation in a self-contained long-running daemon
struct AcmeDaemon {
	/// the ACME server directory to use (available: letsencrypt, arbitrary url)
	#[argh(option, default = "Default::default()")]
	directory: DirectoryConfig,

	/// use the production url instead of the staging url
	#[argh(switch)]
	production: bool,

	/// agree to the terms of service of the acme service
	#[argh(switch)]
	agreeterms: bool,

	/// address to listen on for dns
	#[argh(option, default = "FromStr::from_str(\"127.0.0.2:53\").unwrap()")]
	dnsaddr: std::net::SocketAddr,

	/// amount of time to wait for validation steps to happen, in seconds
	#[argh(option, default = "30")]
	timeout: u64,

	/// paths to directories with public keys to be signed and potentially additional configuration
	#[argh(positional)]
	certificates: Vec<CertificateConfig>,
}
impl AcmeDaemon {
	async fn directory(&self) -> Result<Arc<acme2::Directory>> {
		match self.production {
			false => self.directory.staging().await?.context("No staging directory url available for the specified directory"),
			true => self.directory.production().await,
		}
	}

	async fn login(&self, directory: &Arc<acme2::Directory>) -> Result<Arc<acme2::Account>> {
		acme2::AccountBuilder::new(directory.clone())
		    	.terms_of_service_agreed(self.agreeterms)
		    	.build()
		    	.await
		    	.context("Login failed. You may need to pass some of the following arguments: agreeterms")
	}
}

struct AuthorizationHandler {
	base_name: String,
	challenge_token: String,
}
impl AuthorizationHandler {
	async fn do_lookup(&self, request: &trust_dns_server::server::Request) -> Result<String> {
		use trust_dns_client::rr::*;
		use trust_dns_proto::op::{header::{MessageType}, op_code::OpCode};

		let message_type = request.message_type();
		let op = request.op_code();
		let query = request.query();
		let record_type = query.query_type();
		let name = query.name();
		let expected_name = LowerName::from(Name::from_str(&format!("_acme-challenge.{}", self.base_name))?);


		match (message_type, op, record_type, name) {
			(MessageType::Query, OpCode::Query, RecordType::TXT, name) if name == &expected_name => Ok(self.challenge_token.clone()),
			_ => Err(eyre::eyre!("Unknown query. message={}, op={}, record_type={}, name={}. Expected TXT query for {}.", message_type, op, record_type, name, expected_name)),

		}
	}
}

#[async_trait::async_trait]
impl trust_dns_server::server::RequestHandler for AuthorizationHandler {
	async fn handle_request<R: trust_dns_server::server::ResponseHandler>(&self, request: &trust_dns_server::server::Request, mut response: R) -> trust_dns_server::server::ResponseInfo {

		use trust_dns_server::authority::MessageResponseBuilder;
		use trust_dns_client::rr::*;
		use trust_dns_proto::op::{header::{Header, MessageType}, response_code::ResponseCode};

		let mut header = Header::response_from_request(request.header());
		let builder = MessageResponseBuilder::from_message_request(request);

		header.set_message_type(MessageType::Response);
		match self.do_lookup(request).await {
			Ok(challenge) => {
				println!("Got correct query for challenge, returning {}", challenge);

				let data = rdata::TXT::new(vec![challenge]);
				let mut record = Record::with(request.query().original().name().clone(), RecordType::TXT, 60);
				record.set_data(Some(RData::TXT(data)));

				let records = [record];
				response.send_response(builder.build(header, &records, &[], &[], &[])).await.unwrap()
			},
			Err(e) => {
				println!("Error handling dns query: {:?}", e);
				response.send_response(builder.error_msg(&header, ResponseCode::FormErr)).await.unwrap()
			}
		}
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	let acmedaemon: AcmeDaemon = argh::from_env();

	let directory = acmedaemon.directory().await?;
    let account = acmedaemon.login(&directory).await?;
    let timeout = Duration::from_secs(acmedaemon.timeout);

    for cert in acmedaemon.certificates {
    	let order = cert.start_order(&account)?
	    	.build()
	    	.await?;
	    cert.validate(acmedaemon.dnsaddr, timeout, order.authorizations().await?).await?;

		// Poll the order every 5 seconds until it is in either the
		// `ready` or `invalid` state. Ready means that it is now ready
		// for finalization (certificate creation).
		let order = order.wait_ready(timeout, 3).await?;

		eyre::ensure!(order.status == acme2::OrderStatus::Ready, "Unable to validate domain ownership in less than the timeout ({} seconds)", timeout.as_secs());

		// Generate an RSA private key for the certificate.
		let pkey = acme2::gen_rsa_private_key(4096)?;

		// Create a certificate signing request for the order, and request
		// the certificate.
		let order = order.finalize(acme2::Csr::Automatic(pkey)).await?;

		// Poll the order every 5 seconds until it is in either the
		// `valid` or `invalid` state. Valid means that the certificate
		// has been provisioned, and is now ready for download.
		let order = order.wait_done(timeout, 3).await?;

		eyre::ensure!(order.status == acme2::OrderStatus::Valid, "Unable to sign certificates in less than the timeout ({} seconds)", timeout.as_secs());

		// Download the certificate, and panic if it doesn't exist.
		let cert = order.certificate().await?.unwrap();
		assert!(cert.len() > 1);
	}
    Ok(())
}
