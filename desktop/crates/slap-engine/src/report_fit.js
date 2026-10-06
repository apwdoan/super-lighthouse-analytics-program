/* Page fitting for the PDF export. src/pdf.rs injects this into the copy of a
 * report it prints; an exported HTML report never carries it.
 *
 * A report rarely ends at the foot of its last sheet, and the space left there
 * is space a client sees as wasted. This grows the whole report, text, gauges
 * and spacing alike, by the largest zoom (up to a cap) that keeps the number
 * of sheets it has at full size, so that space goes to legibility instead.
 *
 * Pagination is measured, not estimated: a copy of the page is laid out in
 * columns exactly one sheet's content box in size, and Blink breaks columns
 * with the same fragmentation engine it paginates print with, honouring the
 * same break-inside and break-after rules. One thing print does that columns
 * do not: it repeats a table's header row at the top of each sheet the table
 * continues onto. So wherever a table continues into a new column, the copy
 * gets a copy of the header row there too, and the columns break as the
 * sheets will. The exporter compares the printed page count with the count
 * reported here, and keeps an unzoomed print if the two ever disagree.
 *
 * Parameters arrive in the URL fragment: w and h, the sheet's content box in
 * CSS pixels; cap, the largest zoom allowed; fit=0 to print as it is.
 */
(function () {
  "use strict";
  var params = new URLSearchParams(location.hash.slice(1));
  var width = parseFloat(params.get("w"));
  var height = parseFloat(params.get("h"));
  var cap = parseFloat(params.get("cap"));
  var page = document.querySelector(".page");
  if (params.get("fit") === "0" || !page || !(width > 0) || !(height > 0) || !(cap > 1)) {
    return;
  }

  var sheetsBox = document.createElement("div");
  sheetsBox.style.cssText = "position:absolute;left:-100000px;top:0;" +
    "width:" + width + "px;height:" + height + "px;" +
    "column-width:" + width + "px;column-gap:0;column-fill:auto;";
  var copy = page.cloneNode(true);
  // What @media print does to the page, applied to the copy on screen.
  copy.style.cssText = "max-width:none;margin:0;padding:0;";
  sheetsBox.appendChild(copy);
  document.body.appendChild(sheetsBox);

  var tables = Array.prototype.filter.call(copy.querySelectorAll("table"), function (table) {
    return table.tHead && table.tHead.rows.length === 1;
  });

  // Rows of one column share a left edge, so a row whose left edge differs
  // from the row before it starts a new column. Only edges within the copy
  // are compared, so the zoom's effect on coordinates cancels out.
  function repeatHeaders() {
    tables.forEach(function (table) {
      var head = table.tHead.rows[0];
      var last = head.getBoundingClientRect().left;
      Array.prototype.forEach.call(table.tBodies, function (body) {
        Array.prototype.slice.call(body.rows).forEach(function (row) {
          var left = row.getBoundingClientRect().left;
          if (Math.abs(left - last) > 1) {
            var repeat = head.cloneNode(true);
            repeat.setAttribute("data-repeat", "");
            repeat.style.breakBefore = "column";
            body.insertBefore(repeat, row);
            left = row.getBoundingClientRect().left;
          }
          last = left;
        });
      });
    });
  }

  function sheets(zoom) {
    Array.prototype.forEach.call(copy.querySelectorAll("tr[data-repeat]"), function (row) {
      row.remove();
    });
    copy.style.zoom = String(zoom);
    repeatHeaders();
    return Math.round(sheetsBox.scrollWidth / width);
  }

  var pages = sheets(1);
  var zoom = 1;
  // A long report gains next to nothing (its last sheet is a small share of
  // the whole), and each measurement lays the whole report out again.
  if (pages > 0 && pages <= 40) {
    var lo = 1;
    var hi = cap;
    if (sheets(hi) <= pages) {
      lo = hi;
    } else {
      for (var i = 0; i < 9; i++) {
        var mid = (lo + hi) / 2;
        if (sheets(mid) <= pages) {
          lo = mid;
        } else {
          hi = mid;
        }
      }
    }
    // A hair back from the edge, where one more step pushes a block onto a
    // new sheet: room for rounding, never enough to undo the fit.
    zoom = Math.max(1, Math.floor(lo * 1000 - 1) / 1000);
    if (zoom > 1 && sheets(zoom) > pages) {
      zoom = lo;
    }
  }
  sheetsBox.remove();

  if (zoom > 1) {
    var style = document.createElement("style");
    style.textContent = "@media print { .page { zoom: " + zoom + "; } }";
    document.head.appendChild(style);
  }
  console.log("SLAP-FIT " + JSON.stringify({ pages: pages, zoom: zoom }));
})();
