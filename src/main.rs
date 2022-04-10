use core::time::Duration;
use std::str::FromStr;
use eyre::Result;
use tap::prelude::*;

const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

struct AuthorizationHandler {
	expected_name: trust_dns_client::rr::LowerName,
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


		match (message_type, op, record_type, name) {
			(MessageType::Query, OpCode::Query, RecordType::TXT, name) if name == &self.expected_name => Ok(self.challenge_token.clone()),
			_ => Err(eyre::eyre!("Unknown query. message={}, op={}, record_type={}, name={}. Expected TXT query for {}.", message_type, op, record_type, name, self.expected_name)),

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
	let directory = acme2::DirectoryBuilder::new(LE_STAGING.to_string()).build().await?;
    let account = acme2::AccountBuilder::new(directory.clone())
    	.terms_of_service_agreed(true)
    	.build()
    	.await?;

    let order = acme2::OrderBuilder::new(account.clone())
    	.add_dns_identifier("*.oncloud.org".to_string())
    	.build()
    	.await?;

	let authorizations = order.authorizations().await?;

  	for auth in authorizations {
  		use trust_dns_client::rr::LowerName;
		use trust_dns_client::rr::Name;

    	let challenge = auth.get_challenge("dns-01").expect("DNS challenge");
    	let expected_name = LowerName::from(Name::from_str("_acme-challenge.acme-dns.ohseven.org")?);
    	let challenge_token = challenge.token.as_ref().expect("Challenge Token").clone();
    	println!("challenge: {:?}", challenge_token);

		let socket = tokio::net::UdpSocket::bind("127.0.0.2:53").await?;
    	let mut dns_server = trust_dns_server::server::ServerFuture::new(AuthorizationHandler { expected_name, challenge_token });
    	dns_server.register_socket(socket);

    	let challenge = challenge.validate().await?;

	    // Poll the challenge every 5 seconds until it is in either the
	    // `valid` or `invalid` state.
	    let challenge = challenge.wait_done(Duration::from_secs(240), 3).await?;

	    assert_eq!(challenge.status, acme2::ChallengeStatus::Valid, "DNS-based challenge failed");

	    // You can now remove the challenge file hosted on your webserver.

	    // Poll the authorization every 5 seconds until it is in either the
	    // `valid` or `invalid` state.
	    let authorization = auth.wait_done(Duration::from_secs(240), 3).await?;
	    assert_eq!(authorization.status, acme2::AuthorizationStatus::Valid, "DNS-based challenge failed as not-authorized");
    }

	// Poll the order every 5 seconds until it is in either the
	// `ready` or `invalid` state. Ready means that it is now ready
	// for finalization (certificate creation).
	let order = order.wait_ready(Duration::from_secs(240), 3).await?;

	assert_eq!(order.status, acme2::OrderStatus::Ready);

	// Generate an RSA private key for the certificate.
	let pkey = acme2::gen_rsa_private_key(4096)?;

	// Create a certificate signing request for the order, and request
	// the certificate.
	let order = order.finalize(acme2::Csr::Automatic(pkey)).await?;

	// Poll the order every 5 seconds until it is in either the
	// `valid` or `invalid` state. Valid means that the certificate
	// has been provisioned, and is now ready for download.
	let order = order.wait_done(Duration::from_secs(5), 3).await?;

	assert_eq!(order.status, acme2::OrderStatus::Valid);

	// Download the certificate, and panic if it doesn't exist.
	let cert = order.certificate().await?.unwrap();
	assert!(cert.len() > 1);

    Ok(())
}
