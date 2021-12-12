#ifndef HELPERS_H
#define HELPERS_H

#include "httplib.h"
#include "keys.h"
#include "jwt-cpp/jwt.h"
#include <fstream>
#include <sstream>

class Helper
{
private:
    int auth_count = 0;
    int verify_count = 0;
    double encoding_avg = 0;
    double decoding_avg = 0;

    template <
        class result_t = std::chrono::milliseconds,
        class clock_t = std::chrono::steady_clock,
        class duration_t = std::chrono::milliseconds>
    result_t since(std::chrono::time_point<clock_t, duration_t> const &start)
    {
        return std::chrono::duration_cast<result_t>(clock_t::now() - start);
    }

public:
    void handle_auth(const httplib::Request &req, httplib::Response &res)
    {
        auth_count++;
        auto username = req.matches[1];
        res.set_content(CF_CONST::public_key, "text/plain; charset=UTF-8");
        auto start = std::chrono::steady_clock::now();
        auto token = jwt::create()
                         .set_issuer("auth0")
                         .set_type("JWT")
                         .set_issued_at(std::chrono::system_clock::now())
                         .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{CF_CONST::token_lifetime})
                         .set_subject(username)
                         .sign(jwt::algorithm::rs256("", CF_CONST::private_key, "", ""));
        auto elapsed_ms = since(start).count();
        encoding_avg = (encoding_avg * auth_count + elapsed_ms) / (auth_count + 1);
        res.set_header("Set-Cookie", "token=" + token + "; path=/; HttpOnly");
        std::clog << "new token for: " << username << "\n"
                  << token << std::endl;
    }

    void handle_verify(const httplib::Request &req, httplib::Response &res)
    {
        verify_count++;
        if (req.has_header("Cookie"))
        {
            auto val = req.get_header_value("Cookie");
            std::string cookie_name = val.substr(0, std::string("token=").length());
            if (cookie_name == "token=")
            {
                auto token = val.substr(std::string("token=").length());
                std::clog << "verify: " << token << std::endl;
                auto verify =
                    jwt::verify().allow_algorithm(jwt::algorithm::rs256(CF_CONST::public_key, "", "", "")).with_issuer("auth0");
                try
                {
                    auto start = std::chrono::steady_clock::now();
                    auto decoded = jwt::decode(token);
                    verify.verify(decoded);
                    auto elapsed_us = since<std::chrono::nanoseconds, std::chrono::steady_clock, std::chrono::nanoseconds>(start).count() / 1000;
                    decoding_avg = (decoding_avg * verify_count + elapsed_us) / (verify_count + 1);
                    res.set_content(decoded.get_subject(), "text/plain; charset=UTF-8");
                    return;
                }
                catch (const jwt::error::token_verification_exception &e)
                {
                    res.set_content(e.what(), "text/plain; charset=UTF-8");
                }
                catch (const std::invalid_argument &e)
                {
                    res.set_content(e.what(), "text/plain; charset=UTF-8");
                }
                catch (const std::runtime_error &e)
                {
                    res.set_content(e.what(), "text/plain; charset=UTF-8");
                }
                res.status = 400;
                return;
            }
        }
        res.set_content("JWT token cookie is missing.", "text/plain; charset=UTF-8");
        res.status = 400;
    }

    void handle_readme(const httplib::Request &req, httplib::Response &res)
    {
        std::ifstream f(CF_CONST::readme_txt.c_str());
        if (f.good())
        {
            std::ostringstream ss;
            ss << f.rdbuf();
            std::string content = ss.str();
            res.set_content(content, "text/plain; charset=UTF-8");
        }
        else
        {
            res.set_content("README.txt does not exist.", "text/plain; charset=UTF-8");
            res.status = 404;
        }
    }

    void handle_stats(const httplib::Request &req, httplib::Response &res)
    {
        std::ostringstream ss;
        ss << "/verify has been visited " << verify_count << " times.\n";
        ss << "/auth/<username> has been visited " << auth_count << " times.\n";
        ss << "Average JWT encoding time is " << encoding_avg << " milliseconds.\n";
        ss << "Average JWT decoding time is " << decoding_avg << " microseconds.\n";

        res.set_content(ss.str(), "text/plain; charset=UTF-8");
    }

    void handle_exceptions(const httplib::Request &req, httplib::Response &res, std::exception &e)
    {
        res.status = 500;
        auto fmt = "<h1>Error 500</h1><p>%s</p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, e.what());
        res.set_content(buf, "text/html");
    }
};

#endif
