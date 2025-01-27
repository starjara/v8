// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/maglev/maglev-compilation-unit.h"

#include "src/compiler/js-heap-broker.h"
#include "src/maglev/maglev-compilation-info.h"
#include "src/objects/js-function-inl.h"

namespace v8 {
namespace internal {
namespace maglev {

MaglevCompilationUnit::MaglevCompilationUnit(MaglevCompilationInfo* info,
                                             Handle<JSFunction> function)
    : info_(info),
      shared_function_info_(MakeRef(broker(), function->shared())),
      bytecode_(shared_function_info_.GetBytecodeArray()),
      feedback_(MakeRef(broker(), function->feedback_vector())),
      bytecode_analysis_(bytecode_.object(), zone(), BytecodeOffset::None(),
                         true),
      register_count_(bytecode_.register_count()),
      parameter_count_(bytecode_.parameter_count()) {}

compiler::JSHeapBroker* MaglevCompilationUnit::broker() const {
  return info_->broker();
}

Isolate* MaglevCompilationUnit::isolate() const { return info_->isolate(); }

Zone* MaglevCompilationUnit::zone() const { return info_->zone(); }

bool MaglevCompilationUnit::has_graph_labeller() const {
  return info_->has_graph_labeller();
}

MaglevGraphLabeller* MaglevCompilationUnit::graph_labeller() const {
  DCHECK(has_graph_labeller());
  return info_->graph_labeller();
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
