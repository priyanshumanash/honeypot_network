# 05 — Deployment

*How to run this safely against real traffic — and the ways to do it dangerously.*

> **Read [doc 02](02-design.md) first.** Exposing any service to the internet is a decision with consequences. This document assumes you understand that a honeypot is a service you are *deliberately* making attractive to attackers.

---

## 5.1 The safe default

Out of the box, the honeypot is harmless:

```bash
python -m src.cli run
```

- binds to **127.0.0.1** — unreachable from any other machine
- uses **high ports** (8022, 8080, …) — no root required
- executes nothing, stores nothing dangerous

This is the right mode for development, for the demo, and for understanding the tool. Nothing here can hurt you.

---

## 5.2 Exposing it — the real decision

To capture real attacks, the honeypot has to be reachable. That means binding to a routable interface, which means you have deliberately put an attractive target on the network.

```bash
python -m src.cli run --bind 0.0.0.0
```

```
!! Bound to 0.0.0.0 -- this is reachable from other machines.
   Only do this on a network you intend to expose.
```

Before you do this, understand what you are taking on:

**1. It will be found.** An exposed service is scanned within minutes. Within a day the database fills with credential attempts. That's the point — but be ready for the volume.

**2. Your IP is now publicly a honeypot operator.** Scanners share notes. Some attackers actively avoid known honeypots; others may retaliate.

**3. You are responsible for what the box does.** This being low-interaction, it can't be turned into an attack platform — which is exactly why low-interaction was chosen ([doc 02](02-design.md)). A high-interaction honeypot here would be a genuine liability.

**4. Check your provider's terms.** Many cloud and hosting providers have rules about running honeypots. Some forbid it. Read the acceptable-use policy before you expose anything.

---

## 5.3 Real ports without root

Attackers scan the *standard* ports — 22, 23, 80 — not 8022. To catch them, the standard ports have to reach the honeypot, but binding to ports below 1024 needs root, and **running a network-facing service as root is exactly the mistake you don't want to make.**

The right pattern: run the honeypot unprivileged on high ports, and redirect the low ports to them with a firewall rule.

**Linux (iptables):**

```bash
python -m src.cli run --bind 0.0.0.0        # unprivileged, high ports

sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 8022
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 8023
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

The kernel does the redirect; the honeypot never runs as root. If the honeypot is somehow exploited despite being low-interaction, the attacker lands as an unprivileged user, not root.

**A word on your own SSH:** if you redirect port 22 to the honeypot, move your real SSH to another port *first*, or you'll lock yourself out.

---

## 5.4 Containment

Even low-interaction, defence in depth is right. Run it isolated:

```dockerfile
FROM python:3.11-slim
RUN useradd -m honeypot
WORKDIR /home/honeypot/app
COPY --chown=honeypot . .
RUN pip install --no-cache-dir -r requirements.txt
USER honeypot                       # never root
EXPOSE 8022 8080 8023 8021 2525 6379 3306
CMD ["python", "-m", "src.cli", "run", "--bind", "0.0.0.0"]
```

```bash
docker run -d --name honeypot \
    --read-only \                    # filesystem immutable except the DB volume
    --cap-drop ALL \                 # drop every Linux capability
    --memory 256m --cpus 0.5 \       # bound the blast radius of a flood
    -v honeypot-data:/home/honeypot/app/logs \
    -p 2222:8022 -p 8080:8080 \
    honeypot
```

`--read-only`, `--cap-drop ALL`, non-root user, and resource limits mean that even a hypothetical compromise is contained to a throwaway container with no capabilities and a hard memory ceiling.

For a high-interaction honeypot you would go much further — a dedicated VLAN, egress filtering so the box can't attack outward, and active monitoring. This project doesn't need that, which is the whole argument for low-interaction.

---

## 5.5 Where to run it

| Placement | Catches | Notes |
|---|---|---|
| **Internal network** | Lateral movement, insiders | A honeypot inside your network that lights up means someone is *already in*. The highest-value placement, and the safest |
| **DMZ** | External scanning of your perimeter | Realistic view of what targets your edge |
| **Cloud VM** | Internet background radiation | Cheap, disposable, but check the provider's AUP |
| **Home network** | Curiosity, learning | Fine for study; don't expose your home IP long-term |

The internal placement is the most useful and the least appreciated. External honeypots measure the internet's constant background noise; an *internal* honeypot is a tripwire for a breach that has already happened.

---

## 5.6 Operating it

**Rotate or archive the database.** A busy honeypot generates a lot of rows. `logs/honeypot.db` grows; archive it periodically.

**Watch the dashboard, not the console.** The live console is for demos. In production, run the dashboard ([app.py](../src/app.py)) and check it, or wire the `on_event` callback into your alerting.

**Feed it to a SIEM.** The real value of honeypot data is correlation — a source IP seen here *and* probing your real servers is a strong signal. Exporting to a SIEM is the natural next step ([doc 08](08-future-work.md)).

**Never trust the data as safe.** Every value in that database was typed by an attacker. If you write your own tooling over it, treat it as hostile input — the same way this project's dashboard and store already do.

---

**Previous:** [04 — The services](04-services.md) | **Next:** [06 — Setup & run](06-setup-and-run.md)
