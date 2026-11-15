"""Generate the README diagrams (AWS Architecture Icons, aws4 stencils)."""
import sys
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

INK = "#232F3E"
ANALYTICS = "#8C4FFF"
STORAGE = "#7AA116"
SECURITY = "#DD344C"
MGMT = "#E7157B"
COMPUTE = "#ED7100"
AIML = "#01A88D"
NET = "#8C4FFF"
FONT = "fontFamily=Helvetica;"


class D:
    def __init__(self):
        self.cells = []
        self.n = 1

    def _id(self):
        self.n += 1
        return f"c{self.n}"

    def vertex(self, label, x, y, w, h, style):
        i = self._id()
        self.cells.append(
            f'<mxCell id="{i}" value="{escape(label, {chr(34): "&quot;"})}" style="{style}{FONT}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return i

    def edge(self, s, t, label="", style="", points=(), pos=None):
        i = self._id()
        pts = "".join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in points)
        arr = f'<Array as="points">{pts}</Array>' if points else ""
        gx = f'x="{pos}" ' if pos is not None else ""
        base = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;"
                f"strokeColor=#545B64;strokeWidth=1.5;fontSize=11;fontColor={INK};labelBackgroundColor=#ffffff;")
        self.cells.append(
            f'<mxCell id="{i}" value="{escape(label, {chr(34): "&quot;"})}" style="{base}{style}{FONT}" edge="1" parent="1" source="{s}" target="{t}">'
            f'<mxGeometry {gx}relative="1" as="geometry">{arr}</mxGeometry></mxCell>')
        return i

    # --- AWS shapes -------------------------------------------------------
    def service(self, label, x, y, res, fill, size=56):
        return self.vertex(label, x, y, size, size,
            "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;"
            f"fillColor={fill};strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;"
            "align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;"
            f"shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.{res};")

    def resource(self, label, x, y, shape, fill, size=52, extra=""):
        return self.vertex(label, x, y, size, size,
            "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;"
            f"fillColor={fill};strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;"
            "align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;pointerEvents=1;"
            f"shape=mxgraph.aws4.{shape};" + extra)

    def group(self, label, x, y, w, h, icon, stroke, font=None, dashed=0):
        return self.vertex(label, x, y, w, h,
            "outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=12;fontStyle=1;"
            "container=0;pointerEvents=0;collapsible=0;recursiveResize=0;"
            f"shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.{icon};strokeColor={stroke};fillColor=none;"
            f"verticalAlign=top;align=left;spacingLeft=30;fontColor={font or stroke};dashed={dashed};")

    def box(self, label, x, y, w, h, stroke="#879196", fill="#ffffff", dashed=0, bold=0, align="center",
            valign="middle", size=12, rounded=1):
        return self.vertex(label, x, y, w, h,
            f"rounded={rounded};arcSize=6;whiteSpace=wrap;html=1;strokeColor={stroke};fillColor={fill};"
            f"dashed={dashed};fontColor={INK};fontSize={size};fontStyle={bold};align={align};"
            f"verticalAlign={valign};spacing=8;strokeWidth=1.5;")

    def text(self, label, x, y, w, h, size=12, bold=0, color=INK, align="left"):
        return self.vertex(label, x, y, w, h,
            f"text;html=1;whiteSpace=wrap;strokeColor=none;fillColor=none;align={align};verticalAlign=middle;"
            f"fontSize={size};fontStyle={bold};fontColor={color};")

    def save(self, name, w, h):
        body = "".join(self.cells)
        xml = (f'<mxfile host="drawio"><diagram name="{name}" id="{name}">'
               f'<mxGraphModel dx="{w}" dy="{h}" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" '
               f'arrows="1" fold="1" page="0" pageScale="1" pageWidth="{w}" pageHeight="{h}" math="0" shadow="0">'
               f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root></mxGraphModel></diagram></mxfile>')
        (OUT / f"{name}.drawio").write_text(xml)


# ---------------------------------------------------------------- 1. before / after
d = D()
d.text("Serverless version", 20, 10, 520, 30, size=15, bold=1)
d.group("Customer AWS account", 20, 50, 520, 300, "group_account", "#CD2264")
browser = d.resource("Browser", 50, 150, "client", "#232F3D", 48)
cf = d.service("CloudFront<br>+ S3 (web app)", 140, 146, "cloudfront", NET)
apigw = d.service("API Gateway", 250, 146, "api_gateway", MGMT)
lam = d.service("Lambda", 360, 146, "lambda", COMPUTE)
bed = d.service("Bedrock<br>(writes SQL)", 460, 90, "bedrock", AIML)
ath = d.service("Athena", 460, 220, "athena", ANALYTICS)
d.edge(browser, cf); d.edge(cf, apigw); d.edge(apigw, lam)
d.edge(lam, bed, style="exitX=1;exitY=0.3;entryX=0;entryY=0.5;")
d.edge(lam, ath, style="exitX=1;exitY=0.7;entryX=0;entryY=0.5;")
d.text("~30 resources in one CloudFormation stack.<br>$0 idle, but a Bedrock bill for every question.",
       40, 300, 480, 40, size=12, color="#5A6C86")

d.text("Local version", 600, 10, 520, 30, size=15, bold=1)
d.box("Your laptop", 600, 50, 220, 300, stroke="#7D8998", dashed=1, bold=1, valign="top", align="left")
agent = d.box("AI agent you already use<br><i>(any MCP client)</i>", 620, 100, 180, 60, fill="#F2F3F3")
mcp = d.box("TrailWhisperer<br>MCP server", 620, 230, 180, 60, stroke="#00A4A6", fill="#E6F6F7", bold=1)
d.edge(agent, mcp, "MCP")
d.group("Customer AWS account", 860, 50, 260, 300, "group_account", "#CD2264")
ath2 = d.service("Athena workgroup", 890, 100, "athena", ANALYTICS, 48)
glue2 = d.resource("Glue tables", 1030, 100, "glue_data_catalog", ANALYTICS, 48)
res2 = d.resource("Results bucket", 960, 225, "bucket", STORAGE, 48)
d.edge(mcp, ath2, style="exitX=1;exitY=0.5;entryX=0;entryY=0.5;", points=[(840, 260), (840, 124)])
d.text("4 objects from one command.<br>$0 idle, no Bedrock.", 880, 300, 230, 40, size=12, color="#5A6C86")
d.save("before-after", 1140, 360)

# ---------------------------------------------------------------- 2. architecture
d = D()
d.box("Your laptop", 20, 40, 300, 500, stroke="#7D8998", dashed=1, bold=1, valign="top", align="left")
you = d.resource("You", 146, 80, "user", "#232F3D", 48, extra="labelPosition=right;verticalLabelPosition=middle;verticalAlign=middle;spacingLeft=6;")
agent = d.box("<b>AI agent</b><br>Claude Code, Cursor, Kiro, ...<br>writes the SQL", 50, 190, 240, 70, fill="#F2F3F3")
mcp = d.box("<b>TrailWhisperer MCP server</b><br>"
            "<div style='text-align:left'>• guardrail: is this SQL allowed?<br>"
            "• estimator: how many bytes?<br>• runs it only after you approve</div>",
            50, 330, 240, 120, stroke="#00A4A6", fill="#E6F6F7")
d.edge(you, agent, "question, approval", style="endArrow=block;startArrow=block;startFill=1;")
d.edge(agent, mcp, "MCP: 4 tools", style="endArrow=block;startArrow=block;startFill=1;")

d.group("AWS Cloud", 370, 20, 820, 540, "group_aws_cloud_alt", INK)
d.group("Investigated AWS account", 390, 60, 780, 480, "group_account", "#CD2264")
role = d.resource("Narrow, read-only<br>IAM role", 420, 364, "role", SECURITY, 52)
d.box("Created by <b>init</b>, $0 idle", 540, 110, 290, 410, stroke="#00A4A6", dashed=1, valign="top", size=12)
ath = d.service("Athena workgroup<br>1 GB per-query cutoff", 637, 160, "athena", ANALYTICS)
glue = d.resource("Glue database<br>2 partition-projected tables", 639, 290, "glue_data_catalog", ANALYTICS)
res = d.resource("Results bucket<br>7-day expiry", 639, 410, "bucket", STORAGE)
d.box("Already in the account", 860, 110, 290, 410, stroke="#879196", dashed=1, valign="top", size=12)
ctb = d.resource("CloudTrail logs<br>bucket", 900, 162, "bucket", STORAGE)
trail = d.service("CloudTrail trail", 1060, 160, "cloudtrail", MGMT)
fb = d.resource("Flow log<br>bucket", 900, 352, "bucket", STORAGE)
flow = d.resource("VPC Flow Logs", 1062, 352, "flow_logs", NET)
d.edge(trail, ctb)
d.edge(flow, fb)

d.edge(mcp, role, "assumes", style="exitX=1;exitY=0.5;entryX=0;entryY=0.5;")
d.edge(role, ath, "runs the approved query", style="exitX=0.75;exitY=0;entryX=0;entryY=0.5;", points=[(459, 188)], pos=0.5)
d.edge(role, ctb, "lists object sizes for the estimate (metadata only)",
       style="exitX=0.25;exitY=0;entryX=0.5;entryY=0;dashed=1;", points=[(433, 90), (926, 90)])
d.edge(ath, glue, "table<br>definitions", style="exitX=0;exitY=0.75;entryX=0;entryY=0.5;", points=[(590, 202), (590, 316)])
d.edge(ath, res, "writes results", style="exitX=1;exitY=0.75;entryX=1;entryY=0.5;", points=[(790, 202), (790, 436)])
d.edge(ath, ctb, "reads only the<br>selected days", style="exitX=1;exitY=0.25;entryX=0;entryY=0.5;")
d.save("architecture", 1210, 580)

# ---------------------------------------------------------------- 3. query path
d = D()
MODEL = ("#879196", "#F2F3F3")
CODE = ("#00A4A6", "#E6F6F7")
HUMAN = ("#E29E00", "#FFF4D6")
q = d.resource("Question", 30, 60, "user", "#232F3D", 44)
ctx = d.box("<b>get_investigation_context</b><br>schema, rules, examples", 120, 50, 190, 64, *CODE)
sql = d.box("<b>Agent writes SQL</b>", 350, 50, 150, 64, *MODEL)
g = d.box("<b>check_query: guardrail</b><br>parse with sqlglot,<br>check the tree", 540, 42, 190, 80, *CODE)
est = d.box("<b>check_query: estimate</b><br>sum S3 object sizes<br>of selected days", 800, 42, 190, 80, *CODE)
s3 = d.resource("", 1030, 58, "bucket", STORAGE, 44)
d.edge(q, ctx); d.edge(ctx, sql); d.edge(sql, g)
d.edge(g, est, "allowed")
d.edge(est, s3, style="dashed=1;endArrow=none;")
d.edge(g, sql, "refused, with the reason", style="exitX=0.5;exitY=0;entryX=0.7;entryY=0;strokeColor=#DD344C;fontColor=#DD344C;",
       points=[(635, 18), (455, 18)])
d.edge(est, sql, "too big, or can't be sized", style="exitX=0.5;exitY=0;entryX=0.3;entryY=0;strokeColor=#DD344C;fontColor=#DD344C;",
       points=[(895, -12), (395, -12)])

run = d.box("<b>run_query</b><br>guardrail again, estimate<br>must match the server's", 800, 200, 190, 80, *CODE)
ok = d.box("<b>You approve</b><br>client prompt shows<br>SQL + MB + purpose", 540, 200, 190, 80, *HUMAN)
ath = d.service("Athena workgroup<br>hard scan cutoff", 404, 208, "athena", ANALYTICS, 56)
ans = d.box("<b>Answer</b><br>from at most 200 rows", 120, 208, 190, 64, *MODEL)
d.edge(est, run, "allowed, with an estimate in MB", style="exitX=0.5;exitY=1;entryX=0.5;entryY=0;")
d.edge(run, ok)
d.edge(ok, ath, "yes")
d.edge(ath, ans, "rows")

lx, ly = 120, 345
for i, (label, (st, fi)) in enumerate([("decided by the model", MODEL), ("decided by code", CODE),
                                         ("decided by you", HUMAN)]):
    d.box("", lx + i * 200, ly, 22, 16, st, fi, rounded=0)
    d.text(label, lx + i * 200 + 30, ly - 4, 160, 24, size=12)
d.save("query-path", 1090, 370)
print("ok")
