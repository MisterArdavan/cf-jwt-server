#include "include/helpers.h"
#include <iostream>

int main(int argc, char *argv[])
{
	using namespace httplib;

	Server svr;
	Helper helper;

	// svr.Get(R"(/auth/(.*))", [&](const Request &req, Response &res)
	svr.Get(R"(/auth/([a-zA-Z_0-9]*[a-zA-Z0-9][a-zA-Z_0-9]*))", [&](const Request &req, Response &res)
			{ helper.handle_auth(req, res); });

	svr.Get("/verify", [&](const Request &req, Response &res)
			{ helper.handle_verify(req, res); });

	svr.Get("/README.txt", [&](const Request &req, Response &res)
			{ helper.handle_readme(req, res); });

	svr.Get("/stats", [&](const Request &req, Response &res)
			{ helper.handle_stats(req, res); });

	svr.set_exception_handler([&](const Request &req, Response &res, std::exception &e)
							  { helper.handle_exceptions(req, res, e); });

	svr.listen("localhost", 8080);
}
