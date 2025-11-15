---
title: "Découvrir Hugo - Le générateur de sites statiques"
date: 2025-11-15T11:30:00+01:00
draft: false
tags: ["hugo", "tutoriel", "web"]
categories: ["Tutoriels"]
---

# Qu'est-ce que Hugo?

Hugo est un générateur de sites statiques open-source écrit en Go. Il permet de créer des sites web rapidement et efficacement.

## Installation

Hugo s'installe facilement sur toutes les plateformes:

```bash
# macOS
brew install hugo

# Windows (avec Chocolatey)
choco install hugo-extended

# Linux
snap install hugo
```

## Créer un nouveau site

```bash
hugo new site mon-site
cd mon-site
```

## Ajouter du contenu

```bash
hugo new posts/mon-article.md
```

## Lancer le serveur de développement

```bash
hugo server -D
```

Votre site sera accessible sur `http://localhost:1313`

## Conclusion

Hugo est un excellent choix pour créer des blogs, des sites de documentation ou des portfolios. Sa rapidité et sa simplicité en font un outil idéal pour les développeurs.
