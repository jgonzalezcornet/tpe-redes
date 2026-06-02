/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */

package com.amazon.sample.ui.web;

import com.amazon.sample.ui.config.EndpointProperties;
import io.netty.channel.ChannelOption;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

@RestController
@RequestMapping("/catalog")
public class CatalogVulnProxyController {

  private static final int CONNECT_TIMEOUT_MS = 5000;
  private static final int RESPONSE_TIMEOUT_MS = 10000;

  private final EndpointProperties endpoints;
  private final WebClient webClient;

  @Autowired
  public CatalogVulnProxyController(EndpointProperties endpoints) {
    this.endpoints = endpoints;
    HttpClient httpClient = HttpClient.create()
      .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
      .responseTimeout(Duration.ofMillis(RESPONSE_TIMEOUT_MS));
    this.webClient = WebClient.builder()
      .clientConnector(new ReactorClientHttpConnector(httpClient))
      .build();
  }

  @GetMapping("/search")
  public Mono<ResponseEntity<String>> search(@RequestParam(required = false) String q) {
    String catalogBase = endpoints.getCatalog();
    if (!StringUtils.hasText(catalogBase)) {
      return Mono.just(
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
          "Catalog endpoint not configured"
        )
      );
    }

    return webClient
      .get()
      .uri(catalogBase + "/catalog/search?q={q}", q != null ? q : "")
      .accept(MediaType.APPLICATION_JSON)
      .exchangeToMono(response ->
        response
          .bodyToMono(String.class)
          .defaultIfEmpty("")
          .map(body ->
            ResponseEntity.status(response.statusCode())
              .contentType(MediaType.APPLICATION_JSON)
              .body(body)
          )
      );
  }

  @GetMapping("/image")
  public Mono<ResponseEntity<byte[]>> image(@RequestParam String file) {
    String catalogBase = endpoints.getCatalog();
    if (!StringUtils.hasText(catalogBase)) {
      return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build());
    }

    return webClient
      .get()
      .uri(catalogBase + "/catalog/image?file={file}", file)
      .exchangeToMono(response ->
        response
          .bodyToMono(byte[].class)
          .defaultIfEmpty(new byte[0])
          .map(body -> {
            var builder = ResponseEntity.status(response.statusCode());
            response
              .headers()
              .contentType()
              .ifPresent(builder::contentType);
            return builder.body(body);
          })
      );
  }
}
