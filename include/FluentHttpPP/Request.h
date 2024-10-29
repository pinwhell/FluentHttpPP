#pragma once

#include <string>
#include <unordered_map>
#include <functional>
#include <optional>

namespace FluentHttpPP
{
	enum ERequest {
		EREQ_OK,
		EREQ_ERRUNK,
		EREQ_CONN,
		EREQ_INVALCERTS,
		EREQ_TRANSPORTFAIL,
		EREQ_USRERR
	};

	std::string ERequestToMessage(ERequest req);

	class RequestException : public std::exception {
	public:
		RequestException(ERequest reqException);

		ERequest EReqWhat();
		virtual char const* what() const override;

	private:
		ERequest mReqException;
		std::string mReqMsg;
	};

	class UnknownErrorException : public RequestException {
	public:
		inline UnknownErrorException() : RequestException(EREQ_ERRUNK) {}
	};

	class ConnectionErrorException : public RequestException {
	public:
		inline ConnectionErrorException() : RequestException(EREQ_CONN) {}
	};

	class InvalidCertificatesException : public RequestException {
	public:
		inline InvalidCertificatesException() : RequestException(EREQ_INVALCERTS) {}
	};

	class TransportFailureException : public RequestException {
	public:
		inline TransportFailureException() : RequestException(EREQ_TRANSPORTFAIL) {}
	};

	class UserErrorException : public RequestException {
	public:
		inline UserErrorException(size_t usrErrCode = 0, const std::string& msg = "") : RequestException(EREQ_USRERR), mUserErrorCode(usrErrCode), mUserErrorMsg(msg.empty() ? "User Error Code: " + std::to_string(mUserErrorCode) : msg) {}
		inline char const* what() const override { return mUserErrorMsg.c_str(); }
		size_t mUserErrorCode;
		std::string mUserErrorMsg;
	};

	struct Response {
		int mStatus;
		std::optional<std::string> mBody;

		operator bool()
		{
			return mBody.operator bool();
		}
	};

	using RequestMultiHeader = std::unordered_map<std::string, std::string>;

	template<typename TKey, typename TVal>
	struct MultiKeyValueBuilder {
		MultiKeyValueBuilder& Add(const TKey& key, const TVal& val)
		{
			mKV.insert_or_assign(key, val);
			return *this;
		}

		std::unordered_map<TKey, TVal> Build()
		{
			return mKV;
		}

		std::unordered_map<TKey, TVal> mKV;
	};

	struct HTTPContent {
		std::string mBody;
		std::string mContentType;
	};

	template<typename TContent>
	struct ContentBuilder {
		HTTPContent BuildContent()
		{
			return static_cast<TContent*>(this)->Build().GetContent();
		}
	};

	struct FormURLEncoded {
		FormURLEncoded(const std::unordered_map<std::string, std::string>& multiKv);
		HTTPContent GetContent();
		HTTPContent mContent;
	};

	struct FormURLEncodedBuilder : public ContentBuilder<FormURLEncodedBuilder> {
		FormURLEncodedBuilder& Add(const std::string& key, const std::string& val);
		FormURLEncoded Build();
		MultiKeyValueBuilder<std::string, std::string> mBuilder;
	};

	class Request {
	public:
		Request(
			const std::string& method,
			const std::string& schemaDomainPort,
			const std::string& fullPath,
			const HTTPContent& content,
			const RequestMultiHeader& headers);

		Response Perform() const;

		bool mbHTTPS;
		std::string mSchemaDomainPort;
		std::string mPath;
		std::string mMethod;
		HTTPContent mContent;
		RequestMultiHeader mMultiHeader;
	};

	struct RequestBuilder {
		RequestBuilder();

		RequestBuilder& Reset();
		RequestBuilder& setSchemaDomainPort(const std::string& schemaDomainPort);
		RequestBuilder& setPath(const std::string& path);
		RequestBuilder& setMethod(const std::string& type);
		RequestBuilder& setContent(const HTTPContent& content);
		RequestBuilder& setMultiHeader(const std::unordered_map<std::string, std::string>& multiHeader);
		RequestBuilder& AddMultiHeader(const std::unordered_map<std::string, std::string>& multiHeader);
		RequestBuilder& AddHeader(const std::string& lhs, const std::string& rhs);
		RequestBuilder Clone() const;
		Request Build() const;
		Response Perform() const;

	private:
		std::string mMethod;
		std::string mSchemaDomainPort;
		std::string mPath;
		HTTPContent mContent;
		std::unordered_map<std::string, std::string> mHeaders;
	};
}