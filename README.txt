COMPLETE OMICS LABOS 11.1.7 — CURRENT PACKAGE

Keep this ZIP as the single current installer/archive. Extract it once to a stable folder, such as C:\Complete_Omics_LabOS. On Windows, double-click START_COMPLETE_OMICS_LABOS.bat. Python 3.11 or newer and an internet connection are needed on first setup. The launcher creates its environment and opens http://127.0.0.1:5000.

UPGRADING AN EXISTING LOCAL INSTALLATION
1. Stop the running LabOS server.
2. Make a separate backup of your current lis_v7.db (or configured external database), plus any files in branding/ and your environment settings.
3. Extract this package to your stable LabOS application folder. Keep the existing database and configuration in that folder; do not overwrite them with an empty database. This ZIP deliberately does not contain a database or secret key.
4. Start LabOS. Verify your existing users and orders, then import the clinic CSV through Clinic Management.

Do not delete your database backup when cleaning up old download packages. Simply retaining the current ZIP does not back up clinical records. For cloud installations, retain the configured database and environment variables; use the deployment files in this package.

CHANGES INCLUDED
- 96-well map: click A1–H12 to edit a well, or erase an incorrect assignment.
- Clinic roster: CSV (UTF-8 or Windows-1252) and XLSX; clinic_id and clinic_name required; hart_cadhs and hart_cve optional. Repeated names under different IDs receive an ID suffix. Same-ID reimport matches existing records. Entire import stops on a conflicting ID.
- Prior HL7/FHIR LOINC mapping and earlier LabOS features remain in this package.

The attached clinic roster is not built into this ZIP; upload it in Clinic Management after installation. No live EMR or CRISP interface is implied by the HL7/FHIR export routes.
