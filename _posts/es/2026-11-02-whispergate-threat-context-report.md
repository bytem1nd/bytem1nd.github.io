---
title: Informe sobre el contexto de la amenaza WhisperGate
description: "Informe de Threat Intelligence sobre el wiper WhisperGate con resumen ejecutivo y análisis técnico: Cyber Kill-Chain, TTPs de MITRE ATT&CK, IoCs y medidas de seguridad."
date: "2026-11-02 10:33:43"
image:
  path: /assets/img/posts/whispergate-threat-context-report/01_whispargate-attack-chain.png
  alt: Diagrama de la cadena de ataque de WhisperGate
lang: es
categories: [Threat Intelligence, APT]
tags: [cti, apt, malware, report, mitre-att&ck, ioc, cyber-kill-chain]
---

## Introducción

El 13 de enero de 2022, decenas de sistemas del gobierno ucraniano amanecieron con una nota de rescate en pantalla. Pero no era ransomware: **WhisperGate** simulaba serlo mientras sobrescribía el MBR y destruía los ficheros de sus víctimas, sin ninguna posibilidad real de recuperarlos. Un *wiper* disfrazado, lanzado en vísperas de la invasión rusa de Ucrania.

Este informe nace de una pregunta sencilla: ¿qué necesita saber un equipo de defensa para entender, detectar y frenar una amenaza así? La respuesta se articula en dos niveles de lectura, pensados para públicos distintos, en un mismo documento.

## Descripción del proyecto

El trabajo es un informe de *Threat Intelligence* sobre WhisperGate que combina **resumen ejecutivo** y **análisis técnico**:

- **Nivel ejecutivo:** qué ocurrió, a quién afecta, qué impacto tiene en el negocio y qué decisiones se derivan, sin necesidad de conocimientos técnicos.
- **Nivel técnico:** cómo opera el malware en cada fase del ataque, qué capacidades tiene y qué rastros deja en los sistemas comprometidos.

El informe se estructura en cuatro entregables:

- **Descripción de la Cyber Kill-Chain:** recorrido por las fases del ataque, desde el acceso inicial hasta el impacto destructivo, para entender dónde y cuándo se puede cortar la cadena.
- **TTPs (MITRE ATT&CK):** mapeo de las tácticas, técnicas y procedimientos observados, útil para comparar el comportamiento con otros actores y construir detecciones.
- **Extracción de IoCs:** indicadores de compromiso (hashes, dominios, rutas y artefactos) listos para cargar en herramientas de monitorización y caza de amenazas.
- **Propuesta de medidas de seguridad:** controles preventivos, de detección y de respuesta priorizados para reducir la exposición ante amenazas similares.

Todo ello desde la perspectiva *Blue Team*: no solo analizar el malware, sino convertir ese análisis en información accionable.

## Informe completo

{% include embed-pdf.html src="WhisperGate_context_report.pdf" title="Informe WhisperGate" %}
