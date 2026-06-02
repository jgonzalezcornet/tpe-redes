// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package model

type SearchResponse struct {
	Query    string    `json:"query"`
	Products []Product `json:"products"`
}
