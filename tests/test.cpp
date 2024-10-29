#include <FluentHttpPP/Request.h>
#include <iostream>

using namespace FluentHttpPP;
namespace FHPP = FluentHttpPP;

int main()
{
	auto r = FHPP::RequestBuilder()
		.setSchemaDomainPort("https://example.com")
		.setMethod("POST")
		.Perform();

	std::cout << (*r.mBody);
}