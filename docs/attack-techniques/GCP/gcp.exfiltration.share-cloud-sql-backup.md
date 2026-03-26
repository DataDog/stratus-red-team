---
title: Exfiltrate a Cloud SQL Database via GCS Export
---

# Exfiltrate a Cloud SQL Database via GCS Export

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 


Platform: GCP

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Exfiltrates a Cloud SQL database by exporting it to a GCS bucket, then making the
exported file publicly accessible. This simulates an attacker who has compromised
a GCP service account with Cloud SQL and Storage Admin rights, and uses them to
extract a full database dump and expose it to the internet.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud SQL MySQL 8.0 instance (<code>db-f1-micro</code>)
- Create a GCS bucket to receive the export

<span style="font-variant: small-caps;">Detonation</span>:

- Export the Cloud SQL <code>mysql</code> database to
  <code>gs://&lt;bucket&gt;/export.sql</code> using the Cloud SQL Admin API
- Wait for the export operation to complete
- Grant <code>roles/storage.objectViewer</code> to <code>allUsers</code> on the
  export bucket, making the database dump publicly readable

References:

- https://cloud.google.com/sql/docs/mysql/import-export/exporting
- https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances/export
- https://cloud.google.com/storage/docs/access-control/iam


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.share-cloud-sql-backup
```
## Detection


Identify when a Cloud SQL instance exports its database to GCS by monitoring for
<code>cloudsql.instances.export</code> events in GCP Admin Activity audit logs.
Additionally, alert on <code>storage.setIamPermissions</code> events where a binding
grants <code>roles/storage.objectViewer</code> to <code>allUsers</code> on the
destination bucket, which indicates the exported data is being made publicly accessible.


