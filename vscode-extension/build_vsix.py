"""Package the extension (with the Python scanner bundled) into a .vsix, no Node tooling required.

    python vscode-extension/build_vsix.py
    code --install-extension vscode-extension/dist/secret-sweep-<version>.vsix
"""
import json
import os
import zipfile
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CONTENT_TYPES = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".json" ContentType="application/json"/>
  <Default Extension=".js" ContentType="application/javascript"/>
  <Default Extension=".md" ContentType="text/markdown"/>
  <Default Extension=".py" ContentType="text/x-python"/>
  <Default Extension=".vsixmanifest" ContentType="text/xml"/>
</Types>
"""

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="{name}" Version="{version}" Publisher="{publisher}"/>
    <DisplayName>{display}</DisplayName>
    <Description xml:space="preserve">{description}</Description>
    <Tags>{tags}</Tags>
    <Categories>{categories}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{engine}"/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value=""/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value=""/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace"/>
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value=""/>
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>
  </Assets>
</PackageManifest>
"""


def main() -> str:
    with open(os.path.join(HERE, "package.json"), encoding="utf-8") as fh:
        pkg = json.load(fh)
    manifest = MANIFEST.format(
        name=escape(pkg["name"]), version=escape(pkg["version"]), publisher=escape(pkg["publisher"]),
        display=escape(pkg["displayName"]), description=escape(pkg["description"]),
        tags=escape(",".join(pkg.get("keywords", []))), categories=escape(",".join(pkg.get("categories", []))),
        engine=escape(pkg["engines"]["vscode"]))
    os.makedirs(os.path.join(HERE, "dist"), exist_ok=True)
    out = os.path.join(HERE, "dist", f"{pkg['name']}-{pkg['version']}.vsix")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        z.writestr("extension.vsixmanifest", manifest)
        for name in ("package.json", "extension.js", "README.md"):
            z.write(os.path.join(HERE, name), f"extension/{name}")
        z.write(os.path.join(ROOT, "run.py"), "extension/tool/run.py")
        pkg_dir = os.path.join(ROOT, "secretsweep")
        for name in sorted(os.listdir(pkg_dir)):
            if name.endswith(".py"):
                z.write(os.path.join(pkg_dir, name), f"extension/tool/secretsweep/{name}")
    return out


if __name__ == "__main__":
    print(main())
