var table = new Tabulator("#users-list", {
    height: "70%",
    data: adminData != null && adminData.hasOwnProperty("Users") ? adminData.Users : [],
    layout: "fitColumns",
    pagination: "local",
    paginationSize: 20,
    paginationSizeSelector: [20, 50, 100, 1000],
    movableColumns: true,
    index: "_id",
    cellEdited: updateUser,
    columns: [
        { title: "Name", field: "name", headerFilter: "input", editor: "input" },
        { title: "Email", field: "email", headerFilter: "input" },
        { title: "Role", field: "role", headerFilter: "select", headerFilterParams: {
            "unverified":"unverified",
            "applicant":"applicant",
            "attendee":"attendee",
            "volunteer":"volunteer",
            "organiser":"organiser"}, editor: "select", editorParams: {
                "unverified":"unverified",
                "applicant":"applicant",
                "attendee":"attendee",
                "volunteer":"volunteer",
                "organiser":"organiser"}},
        { title: "Team", field: "team", headerFilter: "input", editor: "input" },
    ]
});

function updateUser(cell) {
    var field = cell._cell.column.field
    var updatedValue = cell._cell.value
    var oldValue = cell._cell.oldValue
    var user = cell._cell.row.data

    var input = confirm("About to update user " + user.name + "(" + user.email + ")\n" +
        "Will change field " + field + ":\n" +
        oldValue + " -> " + updatedValue + "\n" +
        "Continue?")
    if (input === false) { // cancel changes
        // reload to clear local changes
        location.reload()
        return
    }

    $.ajax({
        type: "POST",
        url: "/user/update/" + user._id,
        data: "set={\"" + field + "\":\"" + updatedValue + "\"}",
        success: location.reload,
        dataType: "text"
    });
}
