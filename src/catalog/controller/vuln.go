// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package controller

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws-containers/retail-store-sample-app/catalog/httputil"
	"github.com/aws-containers/retail-store-sample-app/catalog/model"
	"github.com/gin-gonic/gin"
)

const defaultImageBasePath = "/app/catalog-images"

func imageBasePath() string {
	if path := os.Getenv("RETAIL_CATALOG_IMAGE_BASE"); path != "" {
		return path
	}
	return defaultImageBasePath
}

func (c *Controller) Search(ctx *gin.Context) {
	q := ctx.Query("q")

	products, err := c.api.SearchProductsUnsafe(q, ctx.Request.Context())
	if err != nil {
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	if products == nil {
		products = []model.Product{}
	}

	ctx.JSON(http.StatusOK, model.SearchResponse{
		Query:    q,
		Products: products,
	})
}

func (c *Controller) GetImage(ctx *gin.Context) {
	file := ctx.Query("file")
	baseDir := imageBasePath()
	fullPath := filepath.Join(baseDir, file)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	contentType := "application/octet-stream"
	lower := strings.ToLower(file)
	if strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg") {
		contentType = "image/jpeg"
	}

	ctx.Data(http.StatusOK, contentType, data)
}
