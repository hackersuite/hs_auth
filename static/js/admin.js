var table = new Tabulator("#users-list", {
    height: "70%",
    data: adminData.users,
    layout: "fitColumns",
    pagination:"local",
    paginationSize:20,
    paginationSizeSelector:[20, 50, 100, 1000],
    movableColumns:true,
    columns: [
        { title: "Name", field: "name", headerFilter: "input" },
        { title: "Email", field: "email" },
        { title: "Auth Level", field: "auth_level", headerFilter:"number", headerFilterPlaceholder:"at least...", headerFilterFunc:">="},
        { title: "Team", field: "team", headerFilter:"input"},
    ]
});
