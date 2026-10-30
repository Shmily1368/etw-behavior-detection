// SPDX-License-Identifier: AGPL-3.0-only
#include "feature_aggregator.h"
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace etwbehavior;
namespace {
std::vector<int> parse_indices(const std::string& value) {
    std::vector<int> result;
    std::istringstream input(value);
    std::string token;
    if (value.empty()) return result;
    while (std::getline(input, token, ',')) {
        int index = -1;
        const auto parsed = std::from_chars(token.data(), token.data() + token.size(), index);
        if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size())
            throw std::invalid_argument("invalid integer API index");
        result.push_back(index);
    }
    if (value.back() == ',') throw std::invalid_argument("trailing index separator");
    return result;
}
}

int main(int argc, char** argv) {
    try {
        std::string input_path, method_name;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "feature_replay --input resolved-stacks.tsv --method legacy|frequency\n"
                          << "TSV rows: process_key<TAB>comma-separated zero-based API indices.\n"
                          << "One input file is one explicit aggregation window.\n";
                return 0;
            }
            if ((arg == "--input" || arg == "--method") && i + 1 < argc) {
                (arg == "--input" ? input_path : method_name) = argv[++i];
            } else throw std::invalid_argument("unknown or incomplete option");
        }
        if (input_path.empty() || (method_name != "legacy" && method_name != "frequency"))
            throw std::invalid_argument("--input and --method legacy|frequency are required");
        std::ifstream input(input_path);
        if (!input) throw std::runtime_error("cannot open input file");
        FeatureAggregator aggregator(method_name == "legacy" ? FeatureMethod::LegacyApiGroups : FeatureMethod::StackFrequency);
        std::string line;
        std::size_t number = 0;
        while (std::getline(input, line)) {
            ++number;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line.front() == '#') continue;
            const auto tab = line.find('\t');
            if (tab == std::string::npos || line.find('\t', tab + 1) != std::string::npos)
                throw std::invalid_argument("input must have exactly two TSV columns at line " + std::to_string(number));
            const std::string key = line.substr(0, tab);
            if (key.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") != std::string::npos)
                throw std::invalid_argument("process key must use alphanumerics or _.:-");
            aggregator.add(key, parse_indices(line.substr(tab + 1)));
        }
        if (input.bad()) throw std::runtime_error("input read failed");
        for (const auto& [key, state] : aggregator.processes()) {
            // No empty prediction is silently promoted to a normal/benign result.
            std::cout << key << '\t' << aggregator.version() << '\t'
                      << aggregator.legacy_sparse(key) << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "feature_replay: " << error.what() << '\n';
        return 2;
    }
}
