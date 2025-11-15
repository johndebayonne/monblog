---
title: "Comprendre les SACL Windows : Le Guide Complet de l'Audit de Sécurité"
date: 2025-11-15T16:00:00+01:00
draft: false
tags: ["windows", "sécurité", "sacl", "acl", "audit", "powershell"]
categories: ["Sécurité", "Windows", "Tutoriels"]
description: "Découvrez ce que sont les System Access Control Lists (SACL) sous Windows, comment elles fonctionnent et pourquoi elles sont essentielles pour la sécurité de vos systèmes."
---

# Introduction

Si vous travaillez avec Windows Server ou gérez la sécurité de systèmes Windows, vous avez probablement entendu parler des **ACL** (Access Control Lists). Mais connaissez-vous les **SACL** ?

Les **SACL** (System Access Control Lists) sont un composant crucial mais souvent méconnu de la sécurité Windows. Dans cet article, nous allons découvrir en profondeur ce que sont les SACL, comment elles fonctionnent et pourquoi vous devriez vous en préoccuper.

## Qu'est-ce qu'une SACL ?

### Définition Simple

Une **SACL** (System Access Control List) est une liste qui détermine **quels événements d'accès à un objet doivent être audités** dans le journal de sécurité Windows.

En d'autres termes :
- Une **DACL** (Discretionary ACL) vous dit **qui peut faire quoi** ✅❌
- Une **SACL** vous dit **ce qui sera enregistré dans les logs** 📝

### Analogie du Monde Réel

Imaginez un immeuble sécurisé :

**La DACL, c'est comme :**
- Le badge d'accès qui autorise ou refuse l'entrée
- La serrure sur la porte

**La SACL, c'est comme :**
- Le registre de sécurité qui note qui est entré et quand
- Les caméras de surveillance qui enregistrent les accès
- Le journal des visiteurs

## Pourquoi les SACL sont-elles Importantes ?

### 1. Conformité Réglementaire

De nombreuses réglementations exigent l'audit des accès :

- **RGPD** : Traçabilité des accès aux données personnelles
- **HIPAA** : Audit des dossiers médicaux
- **SOX** : Audit des données financières
- **PCI DSS** : Sécurité des données de cartes bancaires

### 2. Détection des Intrusions

Les SACL permettent de détecter :
- Tentatives d'accès non autorisées
- Comportements suspects d'utilisateurs légitimes
- Élévations de privilèges non autorisées
- Modifications de fichiers critiques

### 3. Investigation Post-Incident

Après une faille de sécurité :
- Déterminer **qui** a accédé à quoi
- Comprendre **quand** l'incident s'est produit
- Identifier **comment** l'attaque s'est déroulée
- Évaluer **l'étendue** des dégâts

### 4. Analyse Comportementale

Les SACL permettent d'analyser :
- Les patterns d'accès normaux vs anormaux
- Les heures d'accès inhabituelles
- Les volumes d'accès suspects
- Les corrélations entre différents événements

## DACL vs SACL : Les Différences

| Aspect | DACL | SACL |
|--------|------|------|
| **Objectif** | Contrôle d'accès | Audit |
| **Question** | "Qui peut accéder ?" | "Qui a accédé ?" |
| **Action** | Autorise ou refuse | Enregistre dans les logs |
| **Visibilité** | Immédiate (accès refusé) | Différée (journal d'événements) |
| **Gestion** | Propriétaire de l'objet | Administrateur système |
| **Privilège requis** | Propriétaire | SeSecurityPrivilege |

### Exemple Visuel

```
Fichier : C:\Confidential\salary.xlsx

┌─────────────────────────────────────┐
│         DACL (Permissions)          │
├─────────────────────────────────────┤
│ ✅ Admins      : FullControl        │
│ ✅ HR_Team     : Read, Write         │
│ ❌ Everyone    : Deny All            │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│          SACL (Audit)               │
├─────────────────────────────────────┤
│ 📝 Everyone    : Success + Failure   │
│    Rights      : Read, Write, Delete │
│                                      │
│ 📝 Admins      : Success             │
│    Rights      : FullControl         │
└─────────────────────────────────────┘
```

## Comment Fonctionnent les SACL ?

### Architecture Windows

```
┌──────────────────────────────────────────┐
│         Objet Sécurisé                   │
│         (Fichier, Dossier, Clé Reg)      │
└────────────────┬─────────────────────────┘
                 │
                 ├──► Security Descriptor
                 │
        ┌────────┴────────┐
        │                 │
    ┌───▼───┐        ┌───▼───┐
    │ DACL  │        │ SACL  │
    │       │        │       │
    │ ACE 1 │        │ ACE 1 │
    │ ACE 2 │        │ ACE 2 │
    │ ACE 3 │        │ ACE 3 │
    └───────┘        └───┬───┘
                         │
                         ▼
              ┌──────────────────┐
              │ Security Event   │
              │ Log (Event ID)   │
              │                  │
              │ 4663, 4656...    │
              └──────────────────┘
```

### Les Composants d'une ACE SACL

Chaque entrée (ACE) dans une SACL contient :

1. **Trustee (Identité)** : Pour qui auditer ?
   - Utilisateur : `DOMAIN\jdoe`
   - Groupe : `Everyone`, `Administrators`
   - SID : `S-1-5-21-...`

2. **Access Rights (Droits)** : Quoi auditer ?
   - `Read`, `Write`, `Delete`
   - `Execute`, `Modify`
   - `FullControl`
   - `ChangePermissions`, `TakeOwnership`

3. **Audit Type (Type)** : Quand auditer ?
   - **Success** : Quand l'accès réussit
   - **Failure** : Quand l'accès échoue
   - **Both** : Dans les deux cas

4. **Inheritance Flags** : Propagation ?
   - `ContainerInherit` : Appliquer aux sous-dossiers
   - `ObjectInherit` : Appliquer aux fichiers
   - `InheritOnly` : Uniquement les enfants
   - `NoPropagateInherit` : Pas de propagation

## Exemples Pratiques

### Exemple 1 : Auditer les Accès à un Dossier Sensible

**Objectif** : Savoir qui accède au dossier `C:\Confidential`

```powershell
# Obtenir l'ACL actuelle
$acl = Get-Acl -Path "C:\Confidential"

# Créer une règle d'audit
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",                    # Qui auditer
    "Read,Write,Delete",           # Quels droits
    "Success"                      # Quand (succès)
)

# Ajouter la règle SACL
$acl.SetAuditRule($auditRule)

# Appliquer
Set-Acl -Path "C:\Confidential" -AclObject $acl
```

**Résultat** : Chaque lecture, écriture ou suppression réussie sera enregistrée dans le journal de sécurité.

### Exemple 2 : Détecter les Tentatives d'Accès Non Autorisées

**Objectif** : Alerter sur les échecs d'accès répétés

```powershell
# Auditer les ÉCHECS d'accès
$acl = Get-Acl -Path "C:\Admin"

$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "FullControl",
    "Failure"                      # Auditer les échecs !
)

$acl.AddAuditRule($auditRule)
Set-Acl -Path "C:\Admin" -AclObject $acl
```

**Résultat** : Si quelqu'un essaie d'accéder sans autorisation, un événement sera créé.

### Exemple 3 : Audit Récursif sur Toute une Arborescence

```powershell
function Set-RecursiveSacl {
    param(
        [string]$Path,
        [string]$Identity = "Everyone",
        [string]$Rights = "Read,Write",
        [string]$AuditType = "Success"
    )

    # Obtenir tous les fichiers et dossiers
    Get-ChildItem -Path $Path -Recurse | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $Identity,
            $Rights,
            "ContainerInherit,ObjectInherit",
            "None",
            $AuditType
        )

        $acl.SetAuditRule($auditRule)
        Set-Acl -Path $_.FullName -AclObject $acl

        Write-Host "✅ SACL configurée: $($_.FullName)"
    }
}

# Utilisation
Set-RecursiveSacl -Path "C:\Projects" -AuditType "Success,Failure"
```

## Visualiser les Événements d'Audit

### Event IDs Importants

Les SACL génèrent des événements dans le journal **Security** :

| Event ID | Description |
|----------|-------------|
| **4656** | Demande d'accès à un objet |
| **4658** | Handle fermé vers un objet |
| **4660** | Objet supprimé |
| **4663** | Tentative d'accès à un objet |
| **4670** | Permissions modifiées |
| **4907** | Paramètres d'audit modifiés |

### Lire les Événements avec PowerShell

```powershell
# Afficher les 10 derniers événements d'audit de fichiers
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
} -MaxEvents 10 | Format-List

# Filtrer par utilisateur
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
} | Where-Object {
    $_.Properties[1].Value -like "*jdoe*"
} | Select-Object TimeCreated, Message

# Exporter vers CSV pour analyse
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4663]]" -MaxEvents 1000 |
    Select-Object TimeCreated,
                  @{N='User';E={$_.Properties[1].Value}},
                  @{N='Object';E={$_.Properties[6].Value}},
                  @{N='AccessMask';E={$_.Properties[9].Value}} |
    Export-Csv "C:\Audit\file_access.csv" -NoTypeInformation
```

### Exemple d'Événement 4663

```xml
Event ID: 4663
Source: Microsoft-Windows-Security-Auditing
Level: Information
Keywords: Audit Success

Description:
An attempt was made to access an object.

Subject:
    Security ID:        DOMAIN\jdoe
    Account Name:       jdoe
    Account Domain:     DOMAIN
    Logon ID:           0x12345

Object:
    Object Server:      Security
    Object Type:        File
    Object Name:        C:\Confidential\salary.xlsx
    Handle ID:          0x4a8
    Resource Attributes: -

Process Information:
    Process ID:         0x15c8
    Process Name:       C:\Windows\explorer.exe

Access Request Information:
    Accesses:           READ_DATA
    Access Mask:        0x1
```

## Activer l'Audit des Objets

### Prérequis : Politique d'Audit

Avant que les SACL fonctionnent, vous devez activer l'audit dans la **Stratégie de Groupe** :

```powershell
# Vérifier l'état actuel
auditpol /get /category:"Object Access"

# Activer l'audit du système de fichiers
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Activer l'audit du registre
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Activer l'audit des handles
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
```

### Via Group Policy (GPO)

```
Computer Configuration
  └─ Windows Settings
      └─ Security Settings
          └─ Advanced Audit Policy Configuration
              └─ Object Access
                  ├─ Audit File System [✅ Success ✅ Failure]
                  ├─ Audit Registry [✅ Success ✅ Failure]
                  └─ Audit Handle Manipulation [✅ Success]
```

## Bonnes Pratiques

### 1. Auditez Seulement ce qui est Nécessaire

❌ **Mauvais** :
```powershell
# Trop large, va générer des millions d'événements !
Set-Acl -Path "C:\" -AuditRule (Everyone, FullControl, Success)
```

✅ **Bon** :
```powershell
# Ciblé sur les fichiers critiques
$criticalPaths = @(
    "C:\Finance\*.xlsx",
    "C:\HR\Confidential",
    "C:\Admin\Scripts"
)
foreach ($path in $criticalPaths) {
    # Auditer uniquement les modifications
}
```

### 2. Équilibrez Success vs Failure

- **Success** : Génère beaucoup d'événements (chaque accès normal)
- **Failure** : Génère moins d'événements (tentatives suspectes uniquement)

**Recommandation** :
- Fichiers très sensibles : `Success + Failure`
- Fichiers sensibles : `Failure uniquement`
- Fichiers normaux : Pas d'audit

### 3. Surveillez la Taille des Logs

```powershell
# Vérifier la taille du journal Security
Get-WinEvent -ListLog Security | Select-Object LogName, FileSize, MaximumSizeInBytes

# Configurer la rotation
wevtutil sl Security /ms:1073741824  # 1 GB
wevtutil sl Security /rt:false       # Ne pas écraser
```

### 4. Automatisez l'Analyse

```powershell
# Script quotidien : Détecter les accès suspects
$suspiciousEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    # Accès en dehors des heures de bureau
    $hour = $_.TimeCreated.Hour
    $hour -lt 7 -or $hour -gt 19
}

if ($suspiciousEvents.Count -gt 0) {
    Send-MailMessage `
        -To "security@company.com" `
        -Subject "⚠️ Accès suspects détectés" `
        -Body "Nombre d'événements : $($suspiciousEvents.Count)"
}
```

### 5. Documentez Votre Configuration

```powershell
# Exporter la configuration SACL actuelle
function Export-SaclConfiguration {
    param([string]$RootPath)

    $report = @()

    Get-ChildItem -Path $RootPath -Recurse | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        foreach ($audit in $acl.Audit) {
            $report += [PSCustomObject]@{
                Path = $_.FullName
                Identity = $audit.IdentityReference
                Rights = $audit.FileSystemRights
                Type = $audit.AuditFlags
                Inherited = $audit.IsInherited
            }
        }
    }

    $report | Export-Csv "C:\Audit\SACL_Config_$(Get-Date -Format 'yyyyMMdd').csv"
}
```

## Cas d'Usage Réels

### Cas 1 : Conformité RGPD

```powershell
# Auditer tous les accès aux données personnelles
$gdprFolders = @(
    "C:\CustomerData",
    "C:\PersonalInfo"
)

foreach ($folder in $gdprFolders) {
    $acl = Get-Acl -Path $folder

    # Auditer lecture, modification, suppression
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "Read,Write,Delete,ChangePermissions",
        "ContainerInherit,ObjectInherit",
        "None",
        "Success,Failure"
    )

    $acl.AddAuditRule($auditRule)
    Set-Acl -Path $folder -AclObject $acl
}

# Générer un rapport mensuel pour les audits
```

### Cas 2 : Détection de Ransomware

```powershell
# Surveiller les modifications en masse de fichiers
$baseline = (Get-ChildItem "C:\Data" -Recurse).Count

while ($true) {
    Start-Sleep -Seconds 60

    # Compter les événements de modification des 5 dernières minutes
    $modifications = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4663
        StartTime = (Get-Date).AddMinutes(-5)
    } | Where-Object {
        $_.Properties[9].Value -match "WRITE"
    }

    if ($modifications.Count -gt 100) {
        # Plus de 100 modifications en 5 min = suspect !
        Write-Warning "⚠️ Activité suspecte détectée : $($modifications.Count) modifications"
        # Déclencher une alerte, bloquer l'utilisateur, etc.
    }
}
```

### Cas 3 : Investigation Post-Incident

```powershell
# Après une fuite de données, identifier qui a accédé au fichier
$leakedFile = "C:\Confidential\passwords.txt"

$accessHistory = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
} | Where-Object {
    $_.Properties[6].Value -eq $leakedFile
} | Select-Object TimeCreated,
                  @{N='User';E={$_.Properties[1].Value}},
                  @{N='Action';E={$_.Properties[9].Value}},
                  @{N='Process';E={$_.Properties[11].Value}}

$accessHistory | Format-Table -AutoSize

# Timeline des accès
$accessHistory | Group-Object {$_.TimeCreated.Date} |
    Select-Object Name, Count |
    Sort-Object Name
```

## Limitations et Précautions

### Limitations

1. **Performance** : L'audit intensif peut ralentir le système
2. **Stockage** : Les logs peuvent devenir très volumineux
3. **Complexité** : Difficile à configurer correctement
4. **Privilèges** : Nécessite `SeSecurityPrivilege`

### Précautions

⚠️ **Ne jamais auditer :**
- Les fichiers temporaires (`C:\Temp`, `%TEMP%`)
- Les fichiers système critiques (peut ralentir Windows)
- Les dossiers de pagefile ou hiberfil.sys

⚠️ **Attention à :**
- La rotation des logs (ne pas perdre des données)
- Les alertes de capacité (log plein = plus d'audit)
- Les performances sur les serveurs de fichiers

## Outils Utiles

### Outils Natifs Windows

```powershell
# Auditpol - Gestion de la politique d'audit
auditpol /list /category

# Icacls - Afficher les SACL
icacls "C:\Confidential" /t /c

# Event Viewer
eventvwr.msc
```

### Outils Tiers

- **SysInternals AccessChk** : Vérifier les permissions et SACL
- **Netwrix Auditor** : Solution d'audit complète
- **Varonis** : Analyse comportementale
- **Splunk** : Agrégation et analyse de logs

### Module PowerShell WindowsSacl

```powershell
# Installation (hypothétique)
Install-Module -Name WindowsSacl

# Utilisation simplifiée
Set-WindowsSacl -Path "C:\Data" -AuditUser "Everyone" -Rights "Read,Write"

Get-WindowsSaclAudit -Path "C:\Data" -Days 7
```

## Conclusion

Les **SACL** (System Access Control Lists) sont un outil puissant mais souvent négligé de la sécurité Windows. Elles vous permettent de :

✅ **Savoir** qui accède à vos données
✅ **Détecter** les comportements suspects
✅ **Respecter** les exigences de conformité
✅ **Investiguer** les incidents de sécurité

### Points Clés à Retenir

1. Les **SACL contrôlent l'audit**, pas l'accès
2. Elles nécessitent l'**activation de la politique d'audit**
3. Auditez **uniquement ce qui est nécessaire** (performance)
4. **Surveillez les logs** pour détecter les anomalies
5. **Documentez** votre configuration SACL

### Pour Aller Plus Loin

Dans les prochains articles, nous explorerons :
- Comment créer un module PowerShell pour gérer les SACL
- Automatisation de l'audit avec des scripts
- Intégration avec des outils SIEM
- Analyse forensique avec les événements SACL

---

**Vous utilisez déjà les SACL dans votre infrastructure ? Partagez votre expérience en commentaires !**

## Ressources

- [Microsoft Docs - SACL](https://docs.microsoft.com/windows/security/identity-protection/access-control/access-control-lists)
- [Audit Policy Recommendations](https://docs.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
- [Module PowerShell WindowsSacl](https://github.com/johndebayonne/WindowsSacl) *(à venir)*

---

*Article publié le 15 novembre 2025 par John Debayonne*
