#include <FluentHttpPP/Request.h>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <FluentHttpPP/httplib.h>
#include <FluentHttpPP/Certificates.h>
#include <FluentHttpPP/Crypto/OpenSSL.h>
#include <sstream>
#include <iomanip>
#include <ctype.h>

X509_STORE* FromMemoryMultiCertCreate(SSL_CTX* ctx, const std::string& ca)
{
	static std::openssl_uptr<BIO> cbio(BIO_new_mem_buf(ca.data(), ca.size()));
	X509_STORE* cts = SSL_CTX_get_cert_store(ctx);

	if (!cts)
		return nullptr;

	X509_INFO* itmp;
	int i;
	static STACK_OF(X509_INFO)* inf = PEM_X509_INFO_read_bio(cbio.get(), NULL, NULL, NULL);

	if (!inf)
		return nullptr;

	for (i = 0; i < sk_X509_INFO_num(inf); i++) {
		itmp = sk_X509_INFO_value(inf, i);
		if (itmp->x509) {
			X509_STORE_add_cert(cts, itmp->x509);
		}
		if (itmp->crl) {
			X509_STORE_add_crl(cts, itmp->crl);
		}
	}
	//sk_X509_INFO_pop_free(inf, X509_INFO_free);

	return cts;
}

X509_STORE* GlobalAuthorityCertGet(SSL_CTX* ctx)
{
	/*static X509_STORE* certs = nullptr;

	if (certs)
		return certs;*/

	return FromMemoryMultiCertCreate(ctx, gCertificatesAuthorities.c_str());
}

using namespace FluentHttpPP;
using httplib::Error;

ERequest ErrToEReqErr(Error err)
{
	switch (err)
	{
	case Error::Connection:
	case Error::ExceedRedirectCount:
	case Error::Canceled:
	case Error::SSLConnection:
	case Error::ConnectionTimeout:
	case Error::ProxyConnection:
		return EREQ_CONN;

	case Error::SSLLoadingCerts:
	case Error::SSLServerVerification:
		return EREQ_INVALCERTS;

	case Error::Read:
	case Error::Write:
	case Error::Compression:
		return EREQ_TRANSPORTFAIL;

	default:
		return EREQ_ERRUNK;
	}
}

RequestException ThrowRequestException(const httplib::Result& res)
{
	ERequest error = ErrToEReqErr(res.error());
	switch (error) {
	case EREQ_CONN:
		throw ConnectionErrorException();
	case EREQ_INVALCERTS:
		throw InvalidCertificatesException();
	case EREQ_TRANSPORTFAIL:
		throw TransportFailureException();
	default:
		throw UnknownErrorException();
	}
}

// Function to get error message from ERequest
std::string FluentHttpPP::ERequestToMessage(ERequest req)
{
	static const std::unordered_map<ERequest, std::string> eReqToMessageMap = {
		{ EREQ_OK, "Operation completed successfully."},
		{ EREQ_ERRUNK, "An unknown error occurred."},
		{ EREQ_CONN, "A connection-related error occurred. Please check your network settings."},
		{ EREQ_INVALCERTS, "Invalid SSL certificates. Ensure the certificates are correctly installed and valid."},
		{ EREQ_TRANSPORTFAIL, "Transport error occurred during data transfer. Check your network connection or data integrity."}
		// add other messages as needed
	};

	auto it = eReqToMessageMap.find(req);
	if (it != eReqToMessageMap.end())
	{
		return it->second;
	}
	return eReqToMessageMap.at(EREQ_ERRUNK); // Default to unknown error message if not found
}

RequestException::RequestException(ERequest reqException)
	: mReqException(reqException)
	, mReqMsg(ERequestToMessage(mReqException))
{}

ERequest RequestException::EReqWhat() {
	return mReqException;
}

const char* RequestException::what() const {
	return mReqMsg.c_str();
}

std::string extractDomainAndPort(const std::string& url) {
	// Find the position of "://"
	size_t start = url.find("://");

	// If "://" is found, move the start position to after it
	if (start != std::string::npos) {
		start += 3; // Move past "://"
	}
	else {
		start = 0; // If not found, start from the beginning
	}

	// Find the end of the domain, which is either the first '/' after the domain or the end of the string
	size_t end = url.find('/', start);

	// If '/' is not found, set end to the end of the string
	if (end == std::string::npos) {
		end = url.length();
	}

	// Extract and return the domain and port
	return url.substr(start, end - start);
}

Request::Request(
	const std::string& method,
	const std::string& schemaDomainPort,
	const std::string& fullPath,
	const HTTPContent& content,
	const RequestMultiHeader& headers
)
	: mbHTTPS(schemaDomainPort.find("https") != std::string::npos)
	, mSchemaDomainPort(extractDomainAndPort(schemaDomainPort))
	, mPath(fullPath)
	, mMethod(method)
	, mContent(content)
	, mMultiHeader(headers)
{
	if (mMethod == "GET" &&
		mContent.mContentType == "application/x-www-form-urlencoded" &&
		mPath.find("?") == mPath.npos)
		mPath += "?" + mContent.mBody;
}

template<typename TClient = httplib::Client>
Response PerformHTTP(const Request* req)
{
	TClient client(req->mSchemaDomainPort);
	httplib::Headers headers;
	
	if constexpr (std::is_same_v<TClient, httplib::SSLClient>)
		client.set_ca_cert_store(GlobalAuthorityCertGet(client.ssl_context()));

	for (const auto& header : req->mMultiHeader)
		headers.insert(header);

	if (req->mMethod == "GET")
	{
		auto res = client.Get(req->mPath, headers);
		if (!res) ThrowRequestException(res);
		return { res->status, res->body };
	}

	auto res = client.Post(
		req->mPath,
		headers,
		req->mContent.mBody.c_str(),
		req->mContent.mBody.size(),
		req->mContent.mContentType.c_str()
	);
	if (!res) ThrowRequestException(res);
	return { res->status, res->body };
}

Response Request::Perform() const
{
	if (mbHTTPS)
		return PerformHTTP<httplib::SSLClient>(this);

	return PerformHTTP(this);
}

RequestBuilder::RequestBuilder()
{
	Reset();
}

RequestBuilder& RequestBuilder::Reset()
{
	mMethod = "GET";
	mSchemaDomainPort.clear();
	mPath = "/";
	mHeaders.clear();
	mContent.mBody.clear();
	mContent.mContentType.clear();
	return *this;
}

RequestBuilder& RequestBuilder::setSchemaDomainPort(const std::string& schemaDomainPort)
{
	mSchemaDomainPort = schemaDomainPort;
	return *this;
}

RequestBuilder& RequestBuilder::setPath(const std::string& path)
{
	mPath = path;
	return *this;
}

RequestBuilder& RequestBuilder::setMethod(const std::string& type)
{
	mMethod = type;
	return *this;
}

RequestBuilder& RequestBuilder::setContent(const HTTPContent& content)
{
	mContent = content;
	return *this;
}

RequestBuilder& RequestBuilder::setMultiHeader(const std::unordered_map<std::string, std::string>& multiHeader)
{
	mHeaders = multiHeader;
	return *this;
}

RequestBuilder& RequestBuilder::AddMultiHeader(const std::unordered_map<std::string, std::string>& multiHeader)
{
	for (const auto& kv : multiHeader)
		mHeaders.insert_or_assign(kv.first, kv.second);
	return *this;
}

RequestBuilder& RequestBuilder::AddHeader(const std::string& lhs, const std::string& rhs)
{
	mHeaders.insert_or_assign(lhs, rhs);
	return *this;
}

RequestBuilder RequestBuilder::Clone() const
{
	return RequestBuilder(*this);
}

Request RequestBuilder::Build() const
{
	return Request(mMethod, mSchemaDomainPort, mPath, mContent, mHeaders);
}

Response RequestBuilder::Perform() const
{
	auto& builder = *this;
	return builder
		.Build()
		.Perform();
}

std::string UrlEncode(const std::string& value) {
	std::ostringstream escaped;
	escaped.fill('0');
	escaped << std::hex;

	for (char c : value) {
		// Handle space explicitly
		if (c == ' ') {
			escaped << '+';
		}
		// Handle alphanumeric characters
		else if (isalnum(static_cast<unsigned char>(c)) ||
			c == '-' || c == '_' || c == '.' || c == '~') {
			escaped << c;
		}
		// Handle special characters
		else {
			escaped << '%' << std::setw(2) << std::uppercase
				<< static_cast<int>(static_cast<unsigned char>(c));
		}
	}

	return escaped.str();
}

FormURLEncodedBuilder& FormURLEncodedBuilder::Add(const std::string& key, const std::string& val)
{
	mBuilder.Add(key, val);
	return *this;
}

FormURLEncoded FormURLEncodedBuilder::Build()
{
	return FormURLEncoded(mBuilder.Build());
}

FormURLEncoded::FormURLEncoded(const std::unordered_map<std::string, std::string>& multiKv)
{
	std::string body = "";

	for (const auto& kv : multiKv)
		body += UrlEncode(kv.first) + "=" + UrlEncode(kv.second) + "&";

	if (body.back() == '&')
		body.pop_back();

	mContent = { body, "application/x-www-form-urlencoded" };
}

HTTPContent FormURLEncoded::GetContent()
{
	return mContent;
}