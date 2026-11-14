// Sets the RatScanner icon and version info on the Windows exe (run before injecting the SEA blob).
const fs = require('fs'), path = require('path');
const ResEdit = require('resedit');
const [exe, ico] = process.argv.slice(2);
const pe = ResEdit.NtExecutable.from(fs.readFileSync(exe), { ignoreCert: true });
const res = ResEdit.NtExecutableResource.from(pe);
const icon = ResEdit.Data.IconFile.from(fs.readFileSync(ico));
const groups = ResEdit.Resource.IconGroupEntry.fromEntries(res.entries);
const id = groups.length ? groups[0].id : 1, lang = groups.length ? groups[0].lang : 1033;
ResEdit.Resource.IconGroupEntry.replaceIconsForResource(res.entries, id, lang, icon.icons.map(i => i.data));
const vi = ResEdit.Resource.VersionInfo.fromEntries(res.entries)[0];
if (vi) {
  vi.setStringValues({ lang: 1033, codepage: 1200 }, { ProductName: 'RatScanner', FileDescription: 'RatScanner – local malware scanner', CompanyName: 'RatScanner', InternalName: 'RatScanner', OriginalFilename: 'RatScanner.exe', LegalCopyright: 'RatScanner' });
  vi.removeStringValue({ lang: 1033, codepage: 1200 }, 'Comments');
  vi.outputToResourceEntries(res.entries);
}
res.outputResource(pe);
fs.writeFileSync(exe, Buffer.from(pe.generate()));
console.log('icon + version info set');
