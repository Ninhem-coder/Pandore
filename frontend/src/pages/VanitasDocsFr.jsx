import { ActivityPreview, ApplicationsPreview, Callout, CompliancePreview, DeviceDetailPreview, EolPreview, GroupsPreview, OverviewPreview, Section, SuspiciousActivityPreview } from "./vanitasDocsParts.jsx";

/** French body of the Vanitas documentation — the original hand-written guide (see
 * VanitasDocsTab.jsx). Any change here must be mirrored in VanitasDocsEn.jsx. */
export default function VanitasDocsFr() {
  return (
    <>
      <Section id="intro">
        <p>
          Vanitas est le volet « poste » du dashboard : là où le reste de l'application lit
          les données Microsoft (Intune, Defender), Vanitas parle directement aux machines du
          parc grâce à un petit agent installé dessus. Cet agent tourne en arrière-plan, remonte
          un inventaire régulier au serveur, exécute les règles de conformité qu'on lui confie
          et attend, éventuellement, une commande — installer un logiciel, ouvrir une session de
          dépannage. Le nom vient du memento mori latin : un rappel que rien, sur un poste
          connecté, ne reste vraiment hors de vue bien longtemps.
        </p>
        <p>
          Concrètement, un poste « existe » pour Vanitas à partir du moment où l'agent y a été
          installé et enrôlé — une opération technique faite une fois, à l'installation, qui lui
          délivre un certificat propre à lui. Une fois cette étape passée, tout se pilote depuis
          ce dashboard : plus besoin de se connecter au poste pour savoir s'il est à jour, s'il
          respecte les règles maison, ou s'il tourne encore avec une version de Chrome vieille de
          deux ans.
        </p>
        <p>
          Ce guide couvre l'usage courant du produit, page par page — et, pour chaque page, ce
          qui se passe concrètement au clic sur une ligne ou un bouton, pas seulement la vue de
          premier niveau. Il ne remplace pas une formation à la sécurité ni un mode d'emploi de
          PowerShell : il explique ce que chaque écran montre, ce que chaque bouton déclenche
          réellement, et où se trouvent les vrais points d'attention.
        </p>
      </Section>

      <Section id="roles">
        <p>
          Un compte se situe d'abord à l'un de deux <b>niveaux</b> : <b>administrateur</b> ou{" "}
          <b>lecture seule</b>. Un administrateur voit et fait tout, sans exception — y compris
          ouvrir un terminal sur un poste ou supprimer un groupe — et n'a besoin d'aucun profil.
          Un compte lecture seule, lui, n'a par défaut, sans profil assigné, plus aucun accès à
          Vanitas. Mais ce niveau ne dit rien de ce qu'un tel compte peut réellement faire une
          fois configuré : c'est le <b>rôle</b> assigné via un profil qui définit ça, pas le
          niveau de compte lui-même.
        </p>
        <p>
          Le rôle réel d'un compte lecture seule, c'est donc son <b>profil</b> — assigné par un
          administrateur depuis l'onglet « Profils » — pas une étiquette figée. Un profil est une
          grille : pour chacun des <b>six</b> domaines (postes, terminal, applications,
          conformité, groupes, activités suspectes), on choisit « aucun accès », « lecture » ou
          « lecture et écriture ». Un compte peut donc très bien avoir un accès en écriture
          complet sur plusieurs domaines tout en restant, au niveau de compte, « lecture seule » —
          le niveau ne borne que le maximum théorique (jamais plus qu'un administrateur), le
          profil décide du rôle concret. Un même profil peut être réutilisé sur plusieurs comptes :
          c'est le mécanisme pensé pour construire un rôle sur mesure selon le besoin réel d'une
          équipe — un support qui voit les postes et la conformité mais n'ouvre jamais de terminal
          ni ne pousse d'application, par exemple — plutôt qu'un choix binaire entre tous les
          droits et aucun droit.
        </p>
        <p>
          La page « Profils » a deux sous-onglets : <b>Profils</b> (créer/modifier la grille,
          voir combien de comptes utilisent chacun) et <b>Comptes</b> (créer un compte, lui
          assigner un profil, réinitialiser son mot de passe). Un profil ne peut pas être
          supprimé tant qu'au moins un compte l'utilise encore — il faut d'abord réaffecter ces
          comptes depuis l'onglet Comptes.
        </p>
        <p>
          Deux domaines échappent volontairement à ce découpage bien réglé. Le terminal en
          lecture-écriture revient à donner un accès PowerShell en SYSTEM sur tout poste ciblé —
          un profil peut l'accorder, mais il vaut la peine d'y réfléchir à deux fois avant de le
          faire ; à noter aussi qu'un accès en simple <i>lecture</i> sur ce domaine ne débloque
          rien du tout, contrairement aux autres domaines : pour le terminal, c'est écriture ou
          rien. Et la page « Profils » elle-même reste réservée aux administrateurs : un compte ne
          peut jamais s'auto-attribuer plus de droits qu'il n'en a — impossible aussi de
          rétrograder ou supprimer le dernier compte administrateur restant, pour ne jamais se
          retrouver sans personne aux commandes.
        </p>
      </Section>

      <Section id="overview">
        <p>
          C'est l'écran d'accueil de Vanitas, pensé pour un coup d'œil de dix secondes plutôt
          qu'une lecture approfondie. Le bandeau du haut donne l'état du parc en six chiffres,
          volontairement resserré à ce qui appelle une décision plutôt qu'un inventaire complet
          — chacun cliquable pour sauter directement à la page correspondante : le nombre total
          de postes (avec le nombre en ligne juste en dessous), les activités suspectes non
          traitées, les postes silencieux au sens de l'alerte (seuil plus strict que celui de la
          liste des postes, voir plus bas), les certificats proches de l'expiration, les
          logiciels obsolètes détectés, et un taux de conformité global du parc.
        </p>
        <p>
          En dessous, un bandeau de posture annonce soit « Posture nominale » — rien à signaler
          — soit un résumé des problèmes en cours dès qu'il y en a, suivi d'un graphique de
          l'activité des commandes sur sept jours puis d'une liste unique « Signaux à traiter » :
          postes silencieux, certificats proches de l'expiration, CVE les plus répandues,
          logiciels obsolètes et activités suspectes non traitées, tous mélangés et triés par
          urgence réelle plutôt que comparés côte à côte dans des cartes séparées. Un rail à
          droite regroupe le reste en une seule carte à sections : répartition en ligne/
          silencieux, aperçu des premiers groupes, prochaines expirations de certificat,
          répartition des commandes récentes, et la liste d'alertes récentes détaillée plus loin
          dans ce guide.
        </p>
        <p>
          Cette page ne remplace aucune des autres : elle sert de point de départ pour savoir où
          aller ensuite, pas de tableau de bord définitif. Tout ce qu'elle affiche est recalculé
          côté client à partir de données déjà chargées ailleurs — une seule exception, le « Top
          vulnérabilités », qui vient d'un endpoint dédié.
        </p>
        <OverviewPreview />
      </Section>

      <Section id="devices">
        <p>
          L'onglet « Postes » liste tout le parc enrôlé : nom, état de connexion, ancienneté du
          dernier contact, jours restants avant expiration du certificat, nombre d'applications
          installées, groupes d'appartenance (avec ajout/retrait direct depuis la liste), et la
          dernière commande envoyée. Recherche par nom, filtres rapides (Tous/En ligne/
          Silencieux/Certificat &lt; 30 j) et tri sur chaque colonne.
        </p>
        <p>
          Un poste passe « silencieux » dès qu'il n'a plus contacté le serveur depuis un moment —
          deux seuils coexistent volontairement, et il faut les distinguer. Le premier, plus
          large (sept jours), sert de simple indicateur visuel dans cette liste et dans le
          bandeau de la Vue d'ensemble. Le second, beaucoup plus serré (douze heures par défaut),
          déclenche une vraie alerte journalisée décrite plus loin (« Alertes automatiques ») : un
          poste éteint le week-end ne mérite pas la même attention qu'un poste qui a cessé de
          répondre en pleine journée.
        </p>
        <p>
          Cliquer une ligne ouvre la fiche complète du poste — le cœur de cette page, avec bien
          plus de matière que la simple ligne de liste. En haut, un bandeau d'identité (nom,
          disponibilité, date d'enrôlement, nombre d'applications) porte deux boutons à
          conséquences réelles et très différentes, à ne jamais confondre :
        </p>
        <Callout tone="high" title="« Désinstaller à distance » et « Retirer de l'inventaire » ne font PAS la même chose">
          <p>
            <b>Désinstaller à distance</b> met en file une vraie commande de désinstallation MSI,
            exécutée par l'agent sur le poste lui-même (<code>msiexec /X{"{productCode}"} /qn</code>).
            C'est irréversible et non confirmable depuis le dashboard : le service s'arrête et se
            retire du poste avant même que le résultat ait pu être renvoyé, donc impossible de
            vérifier après coup que ça a bien fonctionné.
          </p>
          <p>
            <b>Retirer de l'inventaire</b>, au contraire, n'agit que côté serveur : il efface la
            fiche du poste et tout son historique du dashboard, et révoque son certificat (l'agent
            ne pourra plus jamais s'authentifier). Si l'agent tourne toujours réellement sur la
            machine physique, il continue de tourner — ce n'est qu'un effacement d'inventaire, pas
            une désinstallation. À réserver à un poste déjà décommissionné par ailleurs.
          </p>
          <p>
            Piège à connaître : le bouton « Désinstaller à distance » reste visible même pour un
            compte qui n'a que la lecture sur le domaine « postes » — le clic échouera avec une
            erreur, le serveur refusant la commande. Le masquage selon le profil n'existe
            aujourd'hui que sur « Retirer de l'inventaire ».
          </p>
        </Callout>
        <p>
          Sous ce bandeau, cinq tuiles de santé cliquables (Certificat, Vulnérabilités, Disque
          système, Applications, Commandes des 7 derniers jours) donnent un résumé en un coup
          d'œil et sautent directement au bon pane. La navigation complète, à gauche, couvre onze
          panes en quatre groupes :
        </p>
        <ul>
          <li>
            <b>Vue d'ensemble</b> — une grille de tuiles de synthèse (identité, disponibilité,
            certificat, disque, vulnérabilités, mises à jour Windows, applications, version de
            l'agent avec bouton de mise à jour si une plus récente existe au catalogue, dernières
            commandes), chacune renvoyant vers le pane détaillé correspondant.
          </li>
          <li>
            <b>Système</b> → <i>Système d'exploitation</i> (build, architecture, mises à jour
            Windows en attente), <i>Matériel</i> (fabricant, BIOS, mémoire, disques, cartes
            graphiques, périphériques PCI — avec un avertissement explicite : le type WMI des
            disques ne distingue pas fiablement SSD et HDD, jamais de badge inventé) et{" "}
            <i>Identité &amp; réseau</i> (utilisateur de session, interfaces réseau).
          </li>
          <li>
            <b>Sécurité</b> → <i>Certificat &amp; enrôlement</i> (renouvellement automatique sous
            30 jours, aucune action manuelle requise), <i>Vulnérabilités</i> et{" "}
            <i>Conformité</i> (résultats déjà décrits plus loin, mais filtrés à ce seul poste), et{" "}
            <i>Activités suspectes</i> (le même journal que l'onglet transverse, filtré à ce
            poste).
          </li>
          <li>
            <b>Inventaire</b> → <i>Applications</i>, la liste des logiciels installés détectés.
          </li>
          <li>
            <b>Administration</b> → <i>Commandes</i> (historique complet, pas seulement les 7
            derniers jours) et <i>Terminal</i> (décrit dans sa propre section plus loin).
          </li>
        </ul>
        <p>
          Beaucoup de champs restent à « — » tant qu'une commande de diagnostic n'a jamais tourné
          sur ce poste (inventaire matériel, diagnostic système) — c'est une dégradation
          gracieuse voulue, pas une anomalie : un formulaire pour lancer la commande manquante
          apparaît directement dans le pane concerné.
        </p>
        <DeviceDetailPreview />
      </Section>

      <Section id="groups">
        <p>
          Un groupe sert à cibler plusieurs postes d'un coup — pousser une application, ou
          pousser une mise à jour de l'agent. Deux façons de le constituer, choisies à la
          création et non modifiables ensuite sans recréer le groupe :
        </p>
        <ul>
          <li>
            <b>Groupe statique</b> — l'appartenance se gère poste par poste, depuis la fiche de
            chaque poste (jamais depuis la page Groupes elle-même) ou depuis le détail du groupe.
            Un poste peut appartenir à plusieurs groupes statiques à la fois.
          </li>
          <li>
            <b>Groupe dynamique</b> — une ou plusieurs conditions (nom du poste, système
            d'exploitation, statut en ligne/silencieux, version de l'agent), combinées en ET ou en
            OU, décident tout seules qui en fait partie. Aucune affectation manuelle n'est possible
            : c'est la règle, et elle seule, qui décide — la fiche du groupe l'indique d'ailleurs
            explicitement (« Membre automatique (règle) » remplace le bouton de retrait).
          </li>
        </ul>
        <p>
          Un groupe peut aussi <b>imbriquer d'autres groupes</b> : les membres du groupe imbriqué
          s'ajoutent à l'union du groupe parent, ce qui permet de composer des ensembles sans
          dupliquer des règles. La fiche d'un groupe affiche par ailleurs deux indicateurs
          agrégés sur ses membres — le nombre moyen de vulnérabilités détectées et un taux de
          risque moyen calculé sur l'échelle CVSS standard (0 à 10). Ce ne sont pas des scores
          inventés maison : une simple moyenne, utile pour repérer d'un coup d'œil qu'un groupe se
          dégrade, pas une note de sécurité certifiée.
        </p>
        <p>
          C'est aussi depuis la fiche d'un groupe qu'on pousse une application (choix d'un
          installeur du catalogue) ou une mise à jour de l'agent vers tous ses membres d'un coup —
          chaque action demande une double confirmation et se traduit par des commandes mises en
          file, visibles ensuite dans « Commandes » (par poste) ou le « Journal » (pour la
          mutation elle-même).
        </p>
        <GroupsPreview />
      </Section>

      <Section id="compliance">
        <p>
          Une règle de conformité est un script PowerShell qui s'exécute périodiquement sur
          chaque poste concerné et renvoie un verdict : conforme, non conforme, ou <i>erreur</i>{" "}
          (le script a planté ou n'a renvoyé aucun code exploitable — un état distinct, jamais
          confondu avec un vrai échec de règle). On la crée depuis l'onglet « Conformité », en
          collant le script et en lui donnant un nom ; le script doit se terminer explicitement
          par <code>exit 0</code> (conforme) ou <code>exit 1</code> (non conforme).
        </p>
        <Callout tone="warn" title="Une règle créée reste désactivée par défaut">
          <p>
            C'est volontaire, pas un oubli. Une règle nouvellement créée — ou dont le script vient
            d'être modifié — ne tourne sur aucun poste tant qu'elle n'a pas été activée
            explicitement, d'un second geste distinct. L'idée est simple : une faute de frappe
            dans un script de conformité ne doit jamais partir en production toute seule, au
            détour d'un enregistrement un peu rapide. Relire, puis activer — dans cet ordre.
          </p>
        </Callout>
        <p>
          Une fois active, une règle produit un résultat par poste concerné, consultable dans son
          détail comme dans la fiche de chaque poste. Ce détail affiche soit le texte brut renvoyé
          par le script, soit — si celui-ci émet en dernière ligne un petit JSON structuré
          (raison, valeur attendue, valeur obtenue) — une présentation lisible avec les deux
          valeurs comparées côte à côte. Modifier le script d'une règle déjà active la repasse
          automatiquement en désactivé, pour le même motif : on ne pousse jamais un changement de
          comportement sans repasser par l'activation volontaire.
        </p>
        <p>
          Ce que cette page ne fait <b>pas</b>, pour être précis : pas de notion de sévérité sur
          une règle (contrairement aux CVE), pas de bouton d'export, pas de remédiation
          automatisée ni d'historique des contrôles précédents — seul le dernier résultat par
          poste est conservé. La seule « remédiation » possible est le texte ou le JSON renvoyé
          par le script lui-même.
        </p>
        <CompliancePreview />
      </Section>

      <Section id="vulnerabilities">
        <p>
          Deux angles complémentaires, deux onglets distincts. « Vulnérabilités » rapproche
          l'inventaire logiciel remonté par chaque poste des CVE connues, une ligne par CVE
          distincte sur tout le parc (produit, score CVSS, sévérité, date de publication, nombre
          de postes exposés). Son détail va plus loin qu'un simple rappel de CVE : quand un avis
          CERT-FR récent en parle, son résumé et son plan d'action apparaissent directement,
          avec un lien vers l'avis d'origine ; sinon, une invitation à vérifier sur NVD. La liste
          des appareils exposés distingue trois statuts — concerné, exclu, indéterminé — selon
          que la version installée correspond ou non à la version réellement vulnérable.
        </p>
        <Callout tone="warn" title="Un très gros chiffre de CVE n'est pas forcément un signal d'alarme">
          <p>
            Le rapprochement ne filtre pas par date de publication : un logiciel très exposé
            historiquement (un navigateur, une suite Adobe) peut faire remonter plusieurs
            centaines, voire milliers, de CVE anciennes sans lien direct avec la version
            réellement installée aujourd'hui. Regardez la sévérité et la date avant de tirer une
            conclusion d'un simple total.
          </p>
        </Callout>
        <p>
          « Logiciels obsolètes » (EOL, <i>end of life</i>) regarde une autre échéance : les
          produits — système d'exploitation, .NET Framework, logiciel — dont la date de fin de
          support est déjà dépassée ou approche à moins de 90 jours, avec la vraie date de fin de
          vie publiée par endoflife.date, pas une estimation. Quand un rapprochement approximatif
          par nom trouve un installeur du même produit déjà au catalogue, un bouton « MàJ au
          catalogue » apparaît en bout de ligne — il ne lance <b>aucune</b> installation lui-même,
          il se contente de basculer vers l'onglet Applications pour que vous poussiez
          l'installeur vous-même, et le rapprochement reste approximatif (à vérifier avant de s'y
          fier les yeux fermés).
        </p>
        <EolPreview />
      </Section>

      <Section id="applications">
        <p>
          Le catalogue d'applications regroupe les installeurs prêts à être déployés. On y dépose
          un fichier <code>.msi</code>, un script <code>.ps1</code> ou un exécutable, en le
          déposant directement ou en le récupérant depuis une release GitHub — une seule fois : il
          reste ensuite disponible pour être poussé vers autant de postes ou de groupes qu'on
          veut. Un compte lecture seule (sans droit d'écriture) voit un catalogue en lecture
          pure, sans aucune action possible ; l'ajout, la modification et le déploiement vivent
          dans la version « Applications » réservée à l'écriture.
        </p>
        <p>
          Pour un installeur MSI, l'assistant demande le mode d'installation — <i>Affichage
          interactif</i> (l'utilisateur peut différer jusqu'à trois fois), <i>Affichage</i> (une
          notification visible, sans interaction possible) ou <i>Silencieux</i> (aucune
          notification) — et le comportement de redémarrage (par défaut de l'installeur, jamais,
          avec confirmation, ou forcé). Pour un script PowerShell ou un exécutable, la commande
          d'installation reste libre, avec un modèle pré-rempli pour PowerShell ; il n'y a alors
          ni mode d'installation ni comportement de redémarrage à choisir, ces notions n'ayant de
          sens que pour un MSI.
        </p>
        <p>
          Déployer se fait depuis deux endroits : la fiche d'un groupe (« Pousser une
          application »), ou la popup « Déployer » ouverte depuis une carte du catalogue, qui
          laisse choisir la cible (un groupe entier ou un poste précis). Le résultat se suit
          ensuite dans « Applications déployées » : taux de réussite global, et par poste le
          détail exact renvoyé par l'agent (Réussi / Échec / En attente du prochain contact de
          l'agent) — reconstruit à partir des commandes déjà envoyées, sans nouvelle donnée
          stockée : un installeur n'y apparaît qu'après avoir été poussé au moins une fois.
        </p>
        <Callout tone="high" title="Un déploiement s'exécute en SYSTEM, sans confirmation sur le poste">
          <p>
            Contrairement au terminal, un déploiement d'application n'ouvre pas de session
            interactive : il s'exécute directement, avec les droits les plus élevés de la machine,
            sans qu'aucune fenêtre ne demande confirmation côté utilisateur. Avant de pousser un
            installeur vers un groupe entier, testez-le sur un seul poste — de préférence un poste
            de test, jamais un poste de production choisi au hasard.
          </p>
        </Callout>
        <ApplicationsPreview />
      </Section>

      <Section id="terminal">
        <p>
          Le terminal ouvre une vraie session PowerShell interactive sur un poste ciblé, avec les
          privilèges du service qui y tourne — c'est-à-dire les droits les plus élevés de la
          machine, SYSTEM. C'est la fonctionnalité la plus puissante de Vanitas, et la plus
          dangereuse mal utilisée : tout ce qui s'y tape s'exécute réellement, tout de suite, sur
          un poste de quelqu'un. Une seule session peut être active à la fois sur un même poste.
        </p>
        <Callout tone="high" title="Contrairement aux autres domaines, une simple lecture n'ouvre rien ici">
          <p>
            Le module « terminal » d'un profil ne connaît que deux états utiles : écriture, ou
            rien du tout. Un profil avec « lecture » seule sur ce domaine ne fait PAS apparaître
            l'onglet Terminal — à la différence de tous les autres modules, où la lecture donne au
            moins une vue en consultation. Il n'existe aujourd'hui aucun mode « regarder sans
            pouvoir taper ».
          </p>
        </Callout>
        <p>
          Ouvrir une session met en file une commande comme une autre (délai de récupération par
          l'agent, jusqu'à environ cinq minutes), avec un message d'attente explicite pendant ce
          temps. Une fois active : une zone d'historique affiche en direct chaque ligne tapée et
          chaque sortie reçue, une ligne de saisie envoie les commandes une par une, et un bouton
          ferme la session à volonté. Quitter la fiche du poste puis y revenir ne rouvre pas
          l'ancienne session : il faut recliquer « Ouvrir un terminal PowerShell », ce qui en
          démarre une nouvelle.
        </p>
        <p>
          Chaque session ouverte, chaque commande qui y transite, est enregistrée dans le journal
          d'activité de façon <b>permanente</b> — contrairement au reste du journal, purgé après
          90 jours, l'historique complet d'une session terminal (ligne par ligne, y compris les
          sorties d'erreur) n'est jamais supprimé : ce n'est pas un canal discret, et ça ne doit
          jamais l'être. À réserver au dépannage ponctuel — un poste qui ne remonte plus son
          inventaire correctement, un diagnostic qu'aucune autre page ne permet de faire à
          distance — plutôt qu'à des actions qui pourraient passer par une règle de conformité ou
          un déploiement d'application, tous deux tracés et rejouables plus proprement.
        </p>
      </Section>

      <Section id="activity">
        <p>
          Chaque action qui modifie quelque chose côté Vanitas laisse une trace ici, sous forme
          de phrase plutôt que de tableau à colonnes : « {"{"}acteur{"}"} {"{"}verbe{"}"}{" "}
          {"{"}cible{"}"} » — par exemple <i>« Nicolas a poussé l'installeur « 7-Zip 24.08 » »</i>{" "}
          ou <i>« Nicolas a désactivé la règle « BitLocker actif » »</i>. Les entrées sont
          classées en quatre catégories — <b>Poste</b>, <b>Application</b>, <b>Conformité</b>,{" "}
          <b>Groupe</b> — filtrables individuellement, avec une recherche libre sur l'acteur, le
          verbe, la cible ou le détail.
        </p>
        <p>
          Le filtre de période propose quatre repères rapides (7, 14, 30, 90 jours) ou une
          période personnalisée via un vrai calendrier à deux mois — les dates au-delà des 90
          jours de rétention sont grisées, non sélectionnables. Cliquer une ligne ouvre le détail
          complet : source (commande poste ou journal d'audit), horodatage précis, paramètres
          JSON décodés, et le détail intégral avec un bouton pour le copier.
        </p>
        <p>
          L'historique au-delà de quatre-vingt-dix jours est purgé automatiquement côté serveur,
          pour éviter une base qui grossit indéfiniment sans qu'on n'y touche jamais —{" "}
          <b>sauf le contenu des sessions terminal</b>, conservé indéfiniment (voir « Terminal
          distant »). Ce journal n'est pas un simple historique de commandes : c'est la réponse à
          la question « qui a fait quoi », utile aussi bien pour comprendre un incident que pour
          vérifier qu'un changement attendu a bien été appliqué.
        </p>
        <ActivityPreview />
      </Section>

      <Section id="alerts">
        <p>
          Vanitas surveille en tâche de fond quatre situations et les journalise dès qu'elles
          apparaissent, visibles dans le bloc « Alertes récentes » de la Vue d'ensemble : un
          poste devenu silencieux (seuil d'alerte par défaut : douze heures — à ne pas confondre
          avec le seuil de sept jours utilisé comme simple indicateur visuel dans la liste des
          postes, deux notions distinctes et configurables indépendamment), un certificat qui
          approche de son expiration (moins de trente jours par défaut), une nouvelle
          vulnérabilité de sévérité <i>critique</i> détectée sur un poste, ou un nouvel échec de
          conformité sur une règle jusque-là respectée.
        </p>
        <p>
          Ces alertes ne se répètent pas à chaque cycle : une fois signalée, une situation ne
          revient dans le journal que si elle change à nouveau — un poste qui redevient silencieux
          après être revenu en ligne, une nouvelle CVE différente de la précédente. Un envoi par
          e-mail peut être ajouté en complément si un serveur de messagerie est configuré côté
          infrastructure ; sans cette configuration, ces alertes restent visibles uniquement ici,
          dans le dashboard.
        </p>
      </Section>

      <Section id="suspicious-activity">
        <p>
          Ce jalon ajoute à l'agent une vraie capacité de détection comportementale, distincte
          de l'inventaire et de la conformité : quatre signaux surveillés en continu sur le
          poste — un processus lancé depuis un chemin inhabituel ou via un outil système
          détourné de son usage normal (LOLBin), un événement marquant du journal Windows
          (création d'un compte administrateur local, connexion RDP hors plage horaire
          habituelle, purge du journal, échecs d'authentification répétés), une connexion
          réseau sortante vers un port ou une adresse hors liste blanche, ou le branchement
          d'un support amovible suivi d'une copie de fichiers.
        </p>
        <Callout tone="warn" title="Le filtrage se fait sur le poste, pas sur le serveur">
          <p>
            L'agent évalue ces règles localement et ne remonte au serveur que les événements
            qui en font matcher une — jamais un flux brut de toute l'activité du poste. Un
            événement qui ne correspond à aucune règle n'apparaîtra donc jamais ici, même après
            coup. Ce choix garde le volume remonté proche de celui d'un inventaire classique
            plutôt que de transformer chaque poste en flux permanent à stocker, mais ça veut
            dire que cette page n'est pas un outil d'investigation sur de la télémétrie brute —
            les journaux Windows du poste restent la seule source complète, avec leur propre
            rétention, généralement plus courte.
          </p>
        </Callout>
        <p>
          Chaque événement porte une sévérité — faible, moyenne ou élevée — sur la même échelle
          que le reste du dashboard (conformité, vulnérabilités), pas le vocabulaire propre à
          Microsoft Defender. Il commence au statut « Nouveau » et se referme en « Accusé
          réception », « Faux positif » ou « Escaladé » : un événement déjà accusé réception
          peut encore être requalifié en faux positif ou escaladé, mais ces deux derniers
          statuts sont définitifs. Le détail d'un événement affiche aussi, quand le poste est
          connu de Microsoft Defender for Endpoint, ses propres alertes actives pour ce même
          poste — deux systèmes de détection différents, une seule fiche de lecture. La même
          vue, filtrée à un seul poste, est aussi disponible directement dans sa fiche détail
          (voir « Les postes »).
        </p>
        <Callout tone="high" title="Des faux positifs sont attendus au démarrage">
          <p>
            Certaines des règles surveillées correspondent aussi à des usages IT parfaitement
            légitimes — un script de déploiement qui invoque PowerShell avec des arguments
            encodés, une astreinte qui se connecte en RDP hors des horaires habituels. Ne
            traitez pas la moindre remontée comme un incident confirmé : cette page existe pour
            trier, pas pour alerter à l'aveugle.
          </p>
        </Callout>
        <SuspiciousActivityPreview />
      </Section>

      <Section id="glossary">
        <p>
          <b>Agent</b> — le programme installé sur un poste, qui le fait exister pour Vanitas.
          <br />
          <b>Enrôlement</b> — l'opération, faite une fois par poste, qui lui délivre son
          certificat et le rattache au serveur.
          <br />
          <b>Poste silencieux</b> — un poste dont l'agent n'a pas contacté le serveur depuis un
          certain temps (sept jours en indicateur simple, douze heures en alerte — deux seuils
          distincts et configurables séparément).
          <br />
          <b>Groupe statique / dynamique</b> — respectivement une liste de postes choisis à la
          main, ou calculée automatiquement à partir d'une ou plusieurs conditions.
          <br />
          <b>Pane</b> — l'une des sous-vues de la fiche d'un poste (Vue d'ensemble, Système
          d'exploitation, Certificat, Terminal…), sélectionnée dans le menu de gauche.
          <br />
          <b>CVE</b> — un identifiant standard de vulnérabilité connue, publié par la communauté
          de la sécurité informatique.
          <br />
          <b>EOL (end of life)</b> — la date à partir de laquelle un logiciel n'est plus maintenu
          par son éditeur, donc plus jamais corrigé.
          <br />
          <b>Profil</b> — un jeu de permissions (lecture, lecture-écriture ou aucun accès) par
          domaine, assignable à un compte lecture seule.
        </p>
      </Section>
    </>
  );
}
