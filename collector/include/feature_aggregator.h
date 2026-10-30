// SPDX-License-Identifier: AGPL-3.0-only
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace etwbehavior {

constexpr std::size_t kFeatureDimensions = 2863;
enum class FeatureMethod { LegacyApiGroups, StackFrequency };

struct ProcessFeatures {
    std::vector<std::uint64_t> counts;
    std::vector<int> previous;
    std::set<int> pending_group;
    std::uint64_t accepted_stacks = 0;
    std::uint64_t repeated_stacks = 0;
};

// A caller-supplied explicit window owns this object. Process keys should
// include a process instance identity when PIDs can be reused.
class FeatureAggregator {
public:
    explicit FeatureAggregator(FeatureMethod method, std::size_t dimensions = kFeatureDimensions);
    void add(const std::string& process_key, const std::vector<int>& indices);
    const std::map<std::string, ProcessFeatures>& processes() const { return processes_; }
    std::map<int, double> normalized(const std::string& process_key) const;
    std::string legacy_sparse(const std::string& process_key) const;
    std::string version() const;
private:
    FeatureMethod method_;
    std::size_t dimensions_;
    std::map<std::string, ProcessFeatures> processes_;
};

} // namespace etwbehavior
