import gulp from "gulp";
import through2 from "through2";
import fs from "fs";
import path from "path";

function cleanTsCompanions() {
    return gulp.src("src/**/*.ts", { read: false })
        .pipe(through2.obj((file, _, cb) => {
            const tsFile = file.path;
            const baseName = tsFile.replace(/\.ts$/, "");

            const companions = [
                `${baseName}.js`,
                `${baseName}.js.map`,
                `${baseName}.d.ts`,
                `${baseName}.d.ts.map`
            ];

            companions.forEach(f => {
                if (fs.existsSync(f)) {
                    fs.unlinkSync(f);
                    console.log("Deleted:", f);
                }
            });

            cb(null, file);
        }));
}

export const clean = cleanTsCompanions;
