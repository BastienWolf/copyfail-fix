# CVE-2026-31431 "Copy Fail" — Detection & Remediation Script

[![CVE](https://img.shields.io/badge/CVE-2026--31431-red)](https://copy.fail/)
[![CVSS](https://img.shields.io/badge/CVSS-7.8%20HIGH-orange)](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Script de détection et remédiation automatique pour la vulnérabilité **Copy Fail** (`CVE-2026-31431`), une faille d'élévation de privilèges locaux dans le noyau Linux affectant toutes les distributions depuis 2017.

## TL;DR — Commande unique

```bash
curl -fsSL https://raw.githubusercontent.com/BastienWolf/copyfail-fix/main/copyfix.sh | sudo bash
```

> ⚠️ Toujours lire un script avant de l'exécuter avec `sudo`. Le contenu est visible dans ce dépôt.

## Ce que fait le script

1. **Vérifie** qu'il tourne en root
2. **Détecte** la distribution et la version du noyau
3. **Évalue** si le système est vulnérable (noyaux 4.14 → 6.18.21 / 6.19.11)
4. **Applique la mitigation immédiate** : désactivation du module `algif_aead` via `/etc/modprobe.d/`
5. **Met à jour le noyau** via le gestionnaire de paquets natif
6. **Vérifie** que la mitigation est bien en place
7. **Indique** si un redémarrage est nécessaire

## Distributions supportées

| Distribution | Gestionnaire | Statut patch |
|---|---|---|
| Ubuntu 20.04 / 22.04 / 24.04 | `apt` | ✅ Patch disponible |
| Ubuntu 26.04 (Resolute)+ | — | 🛡️ Non affecté |
| Debian 11 / 12 | `apt` | ✅ Patch disponible |
| RHEL / CentOS 8+ | `dnf` | ✅ Patch disponible |
| AlmaLinux / Rocky Linux | `dnf` | ✅ Patch disponible |
| Amazon Linux 2023 | `dnf` | ✅ Patch disponible |
| SUSE 15 / openSUSE Leap | `zypper` | ✅ Patch disponible |
| openSUSE Tumbleweed | `zypper` | ✅ Patch disponible (6.19.12) |
| Arch Linux | `pacman` | ✅ Rolling update |
| Autre (générique) | — | ⚠️ Mitigation module uniquement |

## La vulnérabilité en bref

Copy Fail est un bug logique dans le template cryptographique `authencesn` du noyau Linux. Il permet à n'importe quel utilisateur local non privilégié d'écrire 4 octets contrôlés dans le page cache d'un binaire setuid (comme `/usr/bin/su`) et d'obtenir un shell root — avec un script Python de 732 octets, **sans condition de course**, de manière fiable sur toutes les distributions.

- **Introduit** : juillet 2017 (noyau 4.14)
- **CVE** : CVE-2026-31431
- **CVSS** : 7.8 HIGH
- **Vecteur** : Local uniquement (nécessite un accès shell préalable)
- **Impact** : Élévation de privilèges → root, évasion de conteneurs

### Mitigation sans redémarrage

Si vous ne pouvez pas redémarrer immédiatement :

```bash
# Désactiver le module de façon persistante
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf

# Décharger le module si chargé
sudo rmmod algif_aead 2>/dev/null || echo "Module non chargé ou en cours d'usage"

# Vérifier
grep -qE '^algif_aead ' /proc/modules && echo "⚠ Module encore chargé" || echo "✓ Module non actif"
```

> Cette mitigation n'affecte **pas** : dm-crypt/LUKS, kTLS, IPsec/XFRM, OpenSSL, GnuTLS, NSS, SSH.

## Références

- [copy.fail](https://copy.fail/) — Site officiel de la CVE
- [Xint Code Research](https://xint.io/blog/copy-fail-linux-distributions) — Writeup technique
- [CERT-EU Advisory](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Ubuntu Blog](https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available)
- [AlmaLinux Blog](https://almalinux.org/blog/2026-05-01-cve-2026-31431-copy-fail/)

## Licence

MIT
