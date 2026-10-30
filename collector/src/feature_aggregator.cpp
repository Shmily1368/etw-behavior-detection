// SPDX-License-Identifier: AGPL-3.0-only
// Extracted from the author's two PhfDetector implementations.
// The migration map in docs/provenance.md records exact source revisions.
#include "feature_aggregator.h"
#include <cmath>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>

namespace etwbehavior {
FeatureAggregator::FeatureAggregator(FeatureMethod method, std::size_t dimensions)
    : method_(method), dimensions_(dimensions) {
    if (!dimensions || dimensions > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw std::invalid_argument("invalid feature dimension");
}

void FeatureAggregator::add(const std::string& process_key, const std::vector<int>& indices) {
    if (process_key.empty()) throw std::invalid_argument("empty process key");
    for (int index : indices)
        if (index < 0 || static_cast<std::size_t>(index) >= dimensions_)
            throw std::invalid_argument("API index outside the dictionary");
    if (indices.empty()) return;
    auto& state = processes_[process_key];
    if (state.counts.empty()) state.counts.resize(dimensions_, 0);
    if (indices == state.previous) {
        ++state.repeated_stacks;
        return;
    }
    ++state.accepted_stacks;
    if (method_ == FeatureMethod::StackFrequency) {
        for (int index : indices) ++state.counts[index];
    } else {
        // Preserve the legacy transition exactly: a first-frame change commits
        // the previous set; the transition stack is not added to a new set.
        // A trailing pending set is NOT implicitly committed on end-of-input.
        if (!state.previous.empty() && state.previous.front() != indices.front()) {
            for (int index : state.pending_group) ++state.counts[index];
            state.pending_group.clear();
        } else {
            state.pending_group.insert(indices.begin(), indices.end());
        }
    }
    state.previous = indices;
}

std::map<int, double> FeatureAggregator::normalized(const std::string& process_key) const {
    const auto& state = processes_.at(process_key);
    const auto total = std::accumulate(state.counts.begin(), state.counts.end(), std::uint64_t{0});
    std::map<int, double> output;
    if (!total) return output;
    for (std::size_t i = 0; i < dimensions_; ++i) {
        if (state.counts[i]) {
            const double ratio = static_cast<double>(state.counts[i]) / static_cast<double>(total);
            output[static_cast<int>(i)] = std::round(ratio * 10000.0) / 10000.0;
        }
    }
    return output;
}

std::string FeatureAggregator::legacy_sparse(const std::string& process_key) const {
    std::string output;
    for (const auto& [index, weight] : normalized(process_key)) {
        if (!output.empty()) output += ",";
        output += std::to_string(index) + "_";
        if (weight == 1.0) output += "1";
        else {
            auto value = std::to_string(weight);
            value.erase(value.find_last_not_of('0') + 1);
            output += value;
        }
    }
    return output;
}

std::string FeatureAggregator::version() const {
    return method_ == FeatureMethod::LegacyApiGroups ? "legacy-api-groups-v1" : "stack-frequency-v1";
}
} // namespace etwbehavior
