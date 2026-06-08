/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */

package com.amazon.sample.ui.web;

import com.amazon.sample.ui.config.EndpointProperties;
import com.amazon.sample.ui.services.catalog.CatalogService;
import com.amazon.sample.ui.web.util.RequiresCommonAttributes;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.netty.channel.ChannelOption;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

/**
 * Renderiza los resultados de la búsqueda como una página HTML para el usuario
 * final. Comparte la URL {@code /catalog/search} con {@link
 * CatalogVulnProxyController} (que devuelve el JSON crudo para la API y los
 * tests del WAF); se distinguen por el marcador de query {@code view}: el form
 * del navegador envía {@code view=html} y cae acá, mientras que cualquier otro
 * cliente (curl, scripts de WAF, ataques) llega sin {@code view} y obtiene el
 * JSON. Al quedar sobre el mismo path, la búsqueda hereda la misma cobertura y
 * el mismo ajuste de falsos positivos del WAF (ver dist/modsecurity-configmap.yaml).
 */
@Controller
@RequestMapping("/catalog")
@RequiresCommonAttributes
public class CatalogSearchController {

  private static final int CONNECT_TIMEOUT_MS = 5000;
  private static final int RESPONSE_TIMEOUT_MS = 10000;

  private final EndpointProperties endpoints;
  private final CatalogService catalogService;
  private final WebClient webClient;

  @Autowired
  public CatalogSearchController(
    EndpointProperties endpoints,
    CatalogService catalogService
  ) {
    this.endpoints = endpoints;
    this.catalogService = catalogService;
    HttpClient httpClient = HttpClient.create()
      .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
      .responseTimeout(Duration.ofMillis(RESPONSE_TIMEOUT_MS));
    this.webClient = WebClient.builder()
      .clientConnector(new ReactorClientHttpConnector(httpClient))
      .build();
  }

  @GetMapping(value = "/search", params = "view")
  public Mono<String> searchView(
    @RequestParam(required = false, defaultValue = "") String q,
    ServerHttpResponse response,
    Model model
  ) {
    // El navegador navega de una página de búsqueda a la siguiente, así que la
    // query anterior viaja en el header Referer. El CRS inspecciona el Referer y
    // la regla 932206 (RCE Bypass, PL2) matchea cualquier espacio en blanco — una
    // búsqueda de dos palabras dispararía un 403 en la búsqueda siguiente. La
    // exclusión de FP del WAF está acotada a ARGS:q y no cubre el Referer, así
    // que lo cortamos en el origen: el navegador no manda el path+query como
    // referer. Sólo afecta al Referer; el ataque sigue viajando en `q`, que el
    // WAF inspecciona igual.
    response.getHeaders().add("Referrer-Policy", "origin");

    model.addAttribute("query", q);
    model.addAttribute("tags", catalogService.getTags());

    String catalogBase = endpoints.getCatalog();
    if (!StringUtils.hasText(catalogBase)) {
      model.addAttribute("products", Collections.emptyList());
      return Mono.just("search");
    }

    return webClient
      .get()
      .uri(catalogBase + "/catalog/search?q={q}", q)
      .accept(MediaType.APPLICATION_JSON)
      .retrieve()
      .bodyToMono(SearchResult.class)
      .map(result ->
        result.getProducts() != null
          ? result.getProducts()
          : Collections.<ProductHit>emptyList()
      )
      .defaultIfEmpty(Collections.emptyList())
      .onErrorReturn(Collections.emptyList())
      .map(products -> {
        model.addAttribute("products", products);
        return "search";
      });
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  @Data
  static class SearchResult {

    private String query;
    private List<ProductHit> products;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  @Data
  static class ProductHit {

    private String id;
    private String name;
    private String description;
    private int price;
  }
}
