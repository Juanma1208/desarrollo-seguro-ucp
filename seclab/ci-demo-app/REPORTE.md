# Informe de seguridad — Lab Log4Shell

| | |
|---|---|
| **Alumno** | Juanma1208 (@Juanma1208) |
| **Fecha** | 2026-11-26 20:54 |
| **Repositorio** | Juanma1208/desarrollo-seguro-ucp |
| **Rama** | `lab/juanma1208-log4shell` |
| **Herramientas** | gitleaks · semgrep · osv-scanner · trivy + IA (`openai/gpt-oss-120b`) |

## 1. Vulnerabilidad descubierta

El escaneo de dependencias (SCA) detectó **Log4Shell — CVE-2021-44228** en
`org.apache.logging.log4j:log4j-core@2.14.1`: ejecución remota de código (RCE)
crítica cuando la aplicación registra texto controlado por el atacante.

**Hallazgos del gate (antes del parche):** 18 — veredicto **🚫 BLOQUEADO** (exit 1)

| Herramienta | Severidad | Regla / CVE | Ubicacion |
|---|---|---|---|
| deps | HIGH | GHSA-qv9r-c865-cp47 | org.apache.logging.log4j:log4j-api@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-3pxv-7cmr-fjr4 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-6hg6-v5c8-fphq | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-7rjr-3q55-vv33 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-8489-44mv-ggj8 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-h383-gmxw-35v2 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-jfh8-c2jp-5v3q | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-p6xc-xr62-6r2g | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-vc5p-v9hr-52mj | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| trivy | MEDIUM | CVE-2026-49844 | org.apache.logging.log4j:log4j-api@2.14.1 |
| trivy | CRITICAL | CVE-2021-44228 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | CRITICAL | CVE-2021-45046 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | HIGH | CVE-2021-45105 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2021-44832 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2025-68161 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34477 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34479 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34480 | org.apache.logging.log4j:log4j-core@2.14.1 |

## 2. Análisis con IA

### 🤖 Explicacion y remediacion (IA)

**Riesgo principal**  
El proyecto usa **log4j‑api y log4j‑core 2.14.1**, una versión vulnerable a **Log4Shell (CVE‑2021‑44228)** y a varias fallas de deserialización y denegación de servicio que permiten ejecución remota de código o fuga de datos.

**Qué son y por qué importan**  

- **GHSA‑qv9r‑c865‑cp47**, **GHSA‑3pxv‑7cmr‑fjr4**, **GHSA‑6hg6‑v5c8‑fphq**, **GHSA‑7rjr‑3q55‑vv33**, **GHSA‑8489‑44mv‑ggj8**, **GHSA‑h383‑gmxw‑35v2**, **GHSA‑jfh8‑c2jp‑5v3q**, **GHSA‑p6xc‑xr62‑6r2g**, **GHSA‑vc5p‑v9hr‑52mj**: reglas de GitHub que agrupan las vulnerabilidades críticas de Log4j 2.14.1 (JNDI, deserialización, DoS).  
- **CVE‑2021‑44228**: “Log4Shell”. Permite a un atacante ejecutar código arbitrario vía JNDI.  
- **CVE‑2021‑45046**: amplía el alcance de Log4Shell, afectando configuraciones que se creían seguras.  
- **CVE‑2021‑45105**: denegación de servicio por bucle de registro.  
- **CVE‑2021‑44832**: vulnerabilidad de deserialización en `MessagePatternConverter`.  
- **CVE‑2025‑68161**, **CVE‑2026‑49844**, **CVE‑2026‑34477/34479/34480**: vulnerabilidades recientes de deserialización y ejecución remota descubiertas después de 2021.

**Paso concreto para arreglarlo**  

- Edita el `pom.xml` y actualiza ambas dependencias a la última versión estable de la rama 2.x (p. ej. **2.26.1** o superior).  
```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.26.1</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.26.1</version>
</dependency>
```  
- Ejecuta `mvn dependency:tree` para asegurarte de que ninguna otra librería arrastre una versión antigua y exclúyela si es necesario.  
- Reconstruye y vuelve a ejecutar los escáneres; todas las CVE/ GHSA deberían desaparecer.

## 3. Remediación aplicada

Se actualizó `log4j-api` y `log4j-core` a **2.26.1** en `pom.xml`.

> **Lección:** 2.17.1 corrige los CVE de 2021, pero el escaneo aún marcaba CVEs
> de 2025/2026 en log4j; por eso no basta y se sube a la última 2.x estable (2.26.1).

**Hallazgos del gate (después del parche):** 0 — veredicto **✅ PASA** (exit 0)

_Sin hallazgos._

## 4. Evidencia

- Pull Request y corridas del gate (rojo → verde) en GitHub Actions del repo Juanma1208/desarrollo-seguro-ucp:
  <https://github.com/Juanma1208/desarrollo-seguro-ucp/pull/1>
  (commit `b58520c` con log4j 2.14.1: gate en rojo · commit `d22faf1` con log4j 2.26.1: gate en verde).
- Este informe: `seclab/ci-demo-app/REPORTE.md` (en el repo) + subido a **Moodle**.

## Conclusión

El pipeline **bloqueó el merge** hasta corregir la dependencia; la **IA** explicó el
riesgo y la remediación. El gate se re-evalúa contra bases de vulnerabilidades
actualizadas, por eso un fix "histórico" (2.17.1) puede no bastar hoy.

---
_Generado con `seclab/bin/informe.sh` el 2026-11-26 20:54._
