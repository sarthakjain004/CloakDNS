#pragma once

#include <string>
#include <string_view>

namespace cloak {

// Returns the registrable domain ("eTLD+1") of `hostname`. The eTLD+1
// is the suffix you can buy at a registrar — typically the last two
// labels, but for ccTLDs that delegate naming below the country code
// (`.co.uk`, `.co.in`, `.com.au`, ...) it is the last three labels.
//
// Used by the CNAME uncloaker to detect chains that cross registrable
// domains (Safari ITP-style suspicious-cross signal). See
// learnings/safari-cname-defense-and-our-adaptation.md.
//
// Examples:
//   etld_plus_one("news.bbc.co.uk")           == "bbc.co.uk"
//   etld_plus_one("metrics.bigsite.com")      == "bigsite.com"
//   etld_plus_one("a.b.c.example.com")        == "example.com"
//   etld_plus_one("example.com")              == "example.com"
//   etld_plus_one("localhost")                == "localhost"
//   etld_plus_one("")                         == ""
//   etld_plus_one("co.uk")                    == "co.uk"   (suffix only)
//
// Implementation note: hardcoded list of ~35 common multi-label public
// suffixes covers ~99% of real traffic. Not a full Mozilla PSL parse;
// see the learnings doc §8 for the upgrade path. Trailing dots are
// stripped before processing.
std::string etld_plus_one(std::string_view hostname);

}  // namespace cloak
