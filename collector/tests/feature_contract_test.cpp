// SPDX-License-Identifier: AGPL-3.0-only
#include "feature_aggregator.h"
#include <iostream>
#include <stdexcept>

using namespace etwbehavior;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
int main() {
    try {
        FeatureAggregator legacy(FeatureMethod::LegacyApiGroups, 8);
        FeatureAggregator frequency(FeatureMethod::StackFrequency, 8);
        const std::vector<std::vector<int>> sequence{{0,1},{0,1},{0,2},{3,4},{3,5},{6}};
        for (const auto& stack : sequence) {
            legacy.add("p1", stack);
            frequency.add("p1", stack);
        }
        // Fixed expectations from the old transition rule, not computed with
        // a second invocation of the production implementation.
        require(legacy.legacy_sparse("p1") == "0_0.2,1_0.2,2_0.2,3_0.2,5_0.2", "legacy group transition or trailing-group semantics changed");
        require(frequency.legacy_sparse("p1") == "0_0.2222,1_0.1111,2_0.1111,3_0.2222,4_0.1111,5_0.1111,6_0.1111", "frequency counting changed");
        require(legacy.processes().at("p1").repeated_stacks == 1, "duplicate not filtered");
        legacy.add("p2", {7});
        require(legacy.normalized("p2").empty(), "pending legacy tail was incorrectly committed");
        require(legacy.legacy_sparse("p1").find("7_") == std::string::npos, "cross-process mixing");
        bool invalid = false;
        try { legacy.add("p1", {8}); } catch (const std::invalid_argument&) { invalid = true; }
        require(invalid, "out-of-range API accepted");
        invalid = false;
        try { legacy.add("p1", {-1}); } catch (const std::invalid_argument&) { invalid = true; }
        require(invalid, "negative API accepted");
        std::cout << "Feature contracts: legacy transitions, new frequencies, duplicate filtering, isolation, bounds passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
