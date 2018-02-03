const gulp = require('gulp');

gulp.task('build', function () {
    gulp.src('./src/views/**/*')
        .pipe(gulp.dest('./dist/views'));
});