SHELL := /usr/bin/env bash

SRC_DIR := .
OUT_DIR := ../workflows
EXPAND  := ../scripts/expand-workflow.sh

# All input files (recursively)
INPUTS := $(shell find $(SRC_DIR) -type f)

# All top-level workflow inputs (one-to-one with outputs)
WORKFLOW_SRCS := $(wildcard $(SRC_DIR)/*.yml.in)
WORKFLOWS := $(patsubst $(SRC_DIR)/%.yml.in, $(OUT_DIR)/%.yml, $(WORKFLOW_SRCS))

.PHONY: all
all: $(WORKFLOWS)

# Rule: output depends on *all* inputs and the expand script
$(OUT_DIR)/%.yml: $(SRC_DIR)/%.yml.in $(INPUTS) $(EXPAND)
	@echo "Generating $@ from $<"
	@mkdir -p $(OUT_DIR)
	@$(EXPAND) $< > $@
